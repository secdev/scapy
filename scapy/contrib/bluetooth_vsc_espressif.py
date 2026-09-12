# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
#
# scapy.contrib.description = Espressif Bluetooth HCI Vendor-Specific Commands
# scapy.contrib.status = loads
#
# Information sources:
# - https://www.tarlogic.com/blog/esp32-hidden-hci-vendor-commands/
# - esp_bt_vs.h in esp-idf (release/v6.0): https://github.com/espressif/esp-idf


from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteEnumField,
    ByteField,
    FieldLenField,
    LEMACField,
    LEShortField,
    SignedByteField,
    StrField,
    StrLenField,
    XByteField,
    XLEIntField,
)

from scapy.layers.bluetooth import (
    HCI_Command_Hdr,
    HCI_Event_Command_Complete,
    HCI_Event_Vendor,
)


# Espressif vendor-specific event subcodes (event code 0xFF), from esp_bt_vs.h
_esp_vs_evt_subcodes = {
    0x03: "legacy_rem_auth",
    0x05: "afh_chg",
    0x06: "ch_classification",
    0x07: "ch_classification_reporting_mode",
    0xF0: "le_adv_lost",
}


###############################################################################
# Commands (OGF 0x3F)
###############################################################################

class HCI_Cmd_VSC_Espressif_Common_Echo(Packet):
    """
    ESP_BT_VS_COMMON_ECHO (OCF 0x081)

    The controller echoes the payload byte back in the command complete, so this
    doubles as an Espressif-controller fingerprint that works over any transport.
    """
    name = "Espressif Common Echo"
    fields_desc = [XByteField("echo", 0)]


class HCI_Cmd_VSC_Espressif_Rd_New_Conn_Tx_Pwr_Lvl(Packet):
    """ESP_BT_VS_RD_NEW_CONN_TX_PWR_LVL (OCF 0x192)"""
    name = "Espressif Read New Connection TX Power Level"
    fields_desc = []


class HCI_Cmd_VSC_Espressif_Rd_Page_Tx_Pwr_Lvl(Packet):
    """ESP_BT_VS_RD_PAGE_TX_PWR_LVL (OCF 0x194)"""
    name = "Espressif Read Page TX Power Level"
    fields_desc = []


class HCI_Cmd_VSC_Espressif_Rd_Pscan_Tx_Pwr_Lvl(Packet):
    """ESP_BT_VS_RD_PSCAN_TX_PWR_LVL (OCF 0x196)"""
    name = "Espressif Read Page Scan TX Power Level"
    fields_desc = []


class HCI_Cmd_VSC_Espressif_Rd_Inq_Tx_Pwr_Lvl(Packet):
    """ESP_BT_VS_RD_INQ_TX_PWR_LVL (OCF 0x198)"""
    name = "Espressif Read Inquiry TX Power Level"
    fields_desc = []


class HCI_Cmd_VSC_Espressif_Set_Mac(Packet):
    """
    Set MAC address (OCF 0x032) - legacy ROM debug command.

    Sets the controller's public BD_ADDR (6-byte little-endian address). This is
    one of the undocumented ESP32 ROM debug commands (CVE-2025-27840): it exists
    only on the ORIGINAL ESP32 (not the C/S/H series) and only on ESP-IDF
    releases *before* the fix (removed in v5.4.1 / v5.3.3 / v5.2.6 / v5.1.7 /
    v5.0.9 and v6.0+, see advisory AR2025-004), where it answers 0x01 Unknown HCI
    Command.
    """
    name = "Espressif Set MAC Address"
    fields_desc = [LEMACField("bd_addr", None)]


# RivieraWaves dbg-task access sizes for the ROM read/write-memory commands
# (_8_Bit / _16_Bit / _32_Bit are the literal bit widths).
_esp_mem_access_size = {8: "8-bit", 16: "16-bit", 32: "32-bit"}


class HCI_Cmd_VSC_Espressif_Rd_Mem(Packet):
    """
    Read memory (OCF 0x001) - legacy ROM debug command.

    Reads ``length`` bytes (1..128) from ``start_addr`` using ``access_size``-bit
    accesses (8/16/32). One of the undocumented ESP32 ROM debug commands
    (CVE-2025-27840): original ESP32 only, and only on pre-fix ESP-IDF (removed in
    v5.4.1 / v5.3.3 / v5.2.6 / v5.1.7 / v5.0.9 and v6.0+, advisory AR2025-004). The
    command-complete returns status, then a length byte and that many data bytes
    (see HCI_Cmd_Complete_VSC_Espressif_Rd_Mem).
    """
    name = "Espressif Read Memory"
    fields_desc = [XLEIntField("start_addr", 0),
                   ByteEnumField("access_size", 8, _esp_mem_access_size),
                   ByteField("length", 4)]


class HCI_Cmd_VSC_Espressif_Wr_Mem(Packet):
    """
    Write memory (OCF 0x002) - legacy ROM debug command.

    Writes ``data`` to ``start_addr`` using ``access_size``-bit accesses; returns
    status only. Same availability as Read Memory (pre-fix IDF, original ESP32).
    """
    name = "Espressif Write Memory"
    fields_desc = [XLEIntField("start_addr", 0),
                   ByteEnumField("access_size", 8, _esp_mem_access_size),
                   FieldLenField("length", None, length_of="data", fmt="B"),
                   StrLenField("data", b"", length_from=lambda p: p.length)]


class HCI_Cmd_Complete_VSC_Espressif_Common_Echo(Packet):
    """COMMON_ECHO (0xFC81) command complete"""
    name = "Espressif Common Echo complete"
    fields_desc = [XByteField("echo", 0)]


class HCI_Cmd_Complete_VSC_Espressif_Rd_New_Conn_Tx_Pwr_Lvl(Packet):
    """RD_NEW_CONN_TX_PWR_LVL (0xFD92) command complete"""
    name = "Espressif Read New Connection TX Power Level complete"
    fields_desc = [SignedByteField("tx_power_min", 0),
                   SignedByteField("tx_power_max", 0)]


class HCI_Cmd_Complete_VSC_Espressif_Rd_Page_Tx_Pwr_Lvl(Packet):
    """RD_PAGE_TX_PWR_LVL (0xFD94) command complete"""
    name = "Espressif Read Page TX Power Level complete"
    fields_desc = [SignedByteField("tx_power", 0)]


class HCI_Cmd_Complete_VSC_Espressif_Rd_Pscan_Tx_Pwr_Lvl(Packet):
    """RD_PSCAN_TX_PWR_LVL (0xFD96) command complete"""
    name = "Espressif Read Page Scan TX Power Level complete"
    fields_desc = [SignedByteField("tx_power", 0)]


class HCI_Cmd_Complete_VSC_Espressif_Rd_Inq_Tx_Pwr_Lvl(Packet):
    """RD_INQ_TX_PWR_LVL (0xFD98) command complete"""
    name = "Espressif Read Inquiry TX Power Level complete"
    fields_desc = [SignedByteField("tx_power", 0)]


class HCI_Cmd_Complete_VSC_Espressif_Rd_Mem(Packet):
    """Read memory (0xFC01) command complete: a length byte then that many data
    bytes (both after the standard status byte)."""
    name = "Espressif Read Memory complete"
    fields_desc = [FieldLenField("length", None, length_of="data", fmt="B"),
                   StrLenField("data", b"", length_from=lambda p: p.length)]


class HCI_Event_VSC_Espressif(HCI_Event_Vendor):
    """
    Espressif vendor-specific event header (HCI event code 0xFF).

    Registered as an ``HCI_Event_Vendor`` handler, so it replaces the generic
    vendor event whenever the body starts with a known Espressif subcode (see
    ``check``). The first parameter byte is that subcode (see
    ``_esp_vs_evt_subcodes``); the payload is dispatched accordingly.
    """
    name = "Espressif Vendor-Specific Event"
    match_subclass = True
    fields_desc = [ByteEnumField("subcode", 0, _esp_vs_evt_subcodes)]

    @classmethod
    def check(cls, body):
        """
        Checks if the given 0xFF vendor-event body starts with a known
        Espressif subcode.
        """
        return len(body) >= 1 and body[0] in _esp_vs_evt_subcodes


class HCI_Event_VSC_Espressif_Legacy_Rem_Auth(Packet):
    """ESP_BT_VS_LEGACY_REM_AUTH_EVT (subcode 0x03)"""
    name = "Espressif Legacy Remote Auth"
    fields_desc = [LEShortField("conhdl", 0)]


class HCI_Event_VSC_Espressif_Afh_Chg(Packet):
    """ESP_BT_VS_AFH_CHG_EVT (subcode 0x05)"""
    name = "Espressif AFH Change"
    fields_desc = [StrField("data", b"")]


class HCI_Event_VSC_Espressif_Ch_Classification(Packet):
    """ESP_BT_VS_CH_CLASSIFICATION_EVT (subcode 0x06)"""
    name = "Espressif Channel Classification"
    fields_desc = [StrField("data", b"")]


class HCI_Event_VSC_Espressif_Ch_Classification_Reporting_Mode(Packet):
    """ESP_BT_VS_CH_CLASSIFICATION_REPORTING_MODE_EVT (subcode 0x07)"""
    name = "Espressif Channel Classification Reporting Mode"
    fields_desc = [StrField("data", b"")]


class HCI_Event_VSC_Espressif_LE_Adv_Lost(Packet):
    """
    ESP_BT_VS_LE_ADV_LOST_EVT (subcode 0xF0)
    """
    name = "Espressif LE Advertising Report Lost"
    fields_desc = [XLEIntField("nb_lost", 0)]


# Commands: HCI_Command_Hdr -> HCI_Cmd_VSC_Espressif_* (ogf 0x3F, ocf)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Espressif_Rd_Mem,
            ogf=0x3F, ocf=0x001)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Espressif_Wr_Mem,
            ogf=0x3F, ocf=0x002)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Espressif_Set_Mac,
            ogf=0x3F, ocf=0x032)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Espressif_Common_Echo,
            ogf=0x3F, ocf=0x081)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Espressif_Rd_New_Conn_Tx_Pwr_Lvl,
            ogf=0x3F, ocf=0x192)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Espressif_Rd_Page_Tx_Pwr_Lvl,
            ogf=0x3F, ocf=0x194)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Espressif_Rd_Pscan_Tx_Pwr_Lvl,
            ogf=0x3F, ocf=0x196)
bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_Espressif_Rd_Inq_Tx_Pwr_Lvl,
            ogf=0x3F, ocf=0x198)

# Command-complete returns: bound by full opcode (0xFC00 | OCF)
bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Espressif_Rd_Mem, opcode=0xFC01)
bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Espressif_Common_Echo, opcode=0xFC81)
bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Espressif_Rd_New_Conn_Tx_Pwr_Lvl, opcode=0xFD92)
bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Espressif_Rd_Page_Tx_Pwr_Lvl, opcode=0xFD94)
bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Espressif_Rd_Pscan_Tx_Pwr_Lvl, opcode=0xFD96)
bind_layers(HCI_Event_Command_Complete,
            HCI_Cmd_Complete_VSC_Espressif_Rd_Inq_Tx_Pwr_Lvl, opcode=0xFD98)

# Events: the 0xFF vendor event is shared across vendors, so register the
# Espressif event header as a handler
HCI_Event_Vendor.register_handler(HCI_Event_VSC_Espressif)
bind_layers(HCI_Event_VSC_Espressif,
            HCI_Event_VSC_Espressif_Legacy_Rem_Auth, subcode=0x03)
bind_layers(HCI_Event_VSC_Espressif,
            HCI_Event_VSC_Espressif_Afh_Chg, subcode=0x05)
bind_layers(HCI_Event_VSC_Espressif,
            HCI_Event_VSC_Espressif_Ch_Classification, subcode=0x06)
bind_layers(HCI_Event_VSC_Espressif,
            HCI_Event_VSC_Espressif_Ch_Classification_Reporting_Mode, subcode=0x07)
bind_layers(HCI_Event_VSC_Espressif,
            HCI_Event_VSC_Espressif_LE_Adv_Lost, subcode=0xF0)
