# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
#
# scapy.contrib.description = CSR/BlueCore Bluetooth HCI Vendor-Specific Commands
# scapy.contrib.status = loads
#
# Information sources:
# - BlueZ ``tools/csr.h`` / ``tools/csr.c`` (BCCMD framing + varid list)
# - BlueZ ``tools/parser/csr.c`` (BCCMD PDU dissection)

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteField,
    LEShortField,
    LEShortEnumField,
    XStrField,
)

from scapy.layers.bluetooth import (
    HCI_Command_Hdr,
    HCI_Event_Vendor,
)

# BCCMD PDU type (first header word).
_csr_bccmd_pdu_type = {
    0x0000: "getreq",
    0x0001: "getresp",
    0x0002: "setreq",
}

# BCCMD varids (BlueZ ``csr.h``).
# High nibble is an operation class: 0x2xxx read-only info, 0x3xxx iterators
# and parameterised gets, 0x4xxx valueless actions (resets/halts/radio),
# 0x5xxx test, 0x6xxx config, 0x7003 PS-key door.
_csr_varid = {
    0x000b: "ps_clr_all",
    0x000c: "ps_factory_set",
    0x082d: "ps_clr_all_stores",
    0x2801: "bc01_status",
    0x2819: "buildid",
    0x281a: "chipver",
    0x281b: "chiprev",
    0x2825: "interface_version",
    0x282a: "rand",
    0x282c: "max_crypt_key_length",
    0x2836: "chipanarev",
    0x2838: "buildid_loader",
    0x2c00: "bt_clock",
    0x3005: "ps_next",
    0x3006: "ps_size",
    0x3008: "crypt_key_length",
    0x3009: "piconet_instance",
    0x300a: "get_clr_evt",
    0x300b: "get_next_builddef",
    0x3012: "ps_memory_type",
    0x301c: "read_build_name",
    0x4001: "cold_reset",
    0x4002: "warm_reset",
    0x4003: "cold_halt",
    0x4004: "warm_halt",
    0x4005: "init_bt_stack",
    0x4006: "activate_bt_stack",
    0x4007: "enable_tx",
    0x4008: "disable_tx",
    0x4009: "recal",
    0x400d: "ps_factory_restore",
    0x400e: "ps_factory_restore_all",
    0x400f: "ps_defrag_reset",
    0x4010: "kill_vm_application",
    0x4011: "hopping_on",
    0x4012: "cancel_page",
    0x4818: "ps_clr",
    0x481c: "map_sco_pcm",
    0x482e: "single_chan",
    0x5004: "radiotest",
    0x500c: "ps_clr_stores",
    0x6000: "no_variable",
    0x6802: "config_uart",
    0x6805: "panic_arg",
    0x6806: "fault_arg",
    0x6827: "max_tx_power",
    0x682b: "default_tx_power",
    0x7003: "ps",
}


def _bccmd_set_length(p):
    """
    Fill in the BCCMD ``length`` word (total PDU size in 16-bit words: all
    bytes after the ``channel`` byte, divided by 2).
    """
    total_words = (len(p) - 1) // 2
    return p[:3] + total_words.to_bytes(2, "little") + p[5:]


class HCI_Cmd_VSC_CSR_BCCMD(Packet):
    """
    CSR BCCMD command (opcode 0xFC00).
    """
    name = "CSR BCCMD"
    fields_desc = [
        ByteField("channel", 0xC2),
        LEShortEnumField("pdu_type", 0x0000, _csr_bccmd_pdu_type),
        LEShortField("length", None),
        LEShortField("seqno", 0),
        LEShortEnumField("varid", 0, _csr_varid),
        LEShortField("status", 0),
        XStrField("value", b"\x00" * 8),
    ]

    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            p = _bccmd_set_length(p)
        return p


class HCI_Event_VSC_CSR_BCCMD(HCI_Event_Vendor):
    """
    CSR BCCMD response, carried in the HCI vendor-specific event (code 0xFF).

    Registered as an ``HCI_Event_Vendor`` handler, so it replaces the generic
    vendor event whenever the body looks like a BCCMD PDU (see ``check``).
    """
    name = "CSR BCCMD response"
    match_subclass = True
    fields_desc = [
        ByteField("channel", 0xC2),
        LEShortEnumField("pdu_type", 0x0001, _csr_bccmd_pdu_type),
        LEShortField("length", None),
        LEShortField("seqno", 0),
        LEShortEnumField("varid", 0, _csr_varid),
        LEShortField("status", 0),
        XStrField("value", b""),
    ]

    @classmethod
    def check(cls, body):
        """
        Checks if the given 0xFF vendor-event body is a BCCMD PDU: a 0xC2
        channel byte followed by the 5-word (10-byte) header.
        """
        return len(body) >= 11 and body[0] == 0xC2

    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            p = _bccmd_set_length(p)
        return p


bind_layers(HCI_Command_Hdr, HCI_Cmd_VSC_CSR_BCCMD, ogf=0x3F, ocf=0x000)

# The BCCMD reply rides the generic 0xFF vendor event, which is shared with
# other vendors. Rather than rebinding that event code (split_layers), register
# the response as a handler so it is only used when the body looks like a BCCMD
# PDU (see its ``check``). This lets the CSR contrib coexist with other vendor
# contribs that use the same event code.
HCI_Event_Vendor.register_handler(HCI_Event_VSC_CSR_BCCMD)
