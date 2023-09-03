# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
Default USB frames & Basic implementation
"""

# TODO: support USB headers for Linux and Darwin (usbmon/netmon)
# https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-usb.c  # noqa: E501

from scapy.config import conf
from scapy.compat import chb
from scapy.data import DLT_USBPCAP
from scapy.fields import ByteField, XByteField, ByteEnumField, LEShortField, \
    LEShortEnumField, LEIntField, LEIntEnumField, XLELongField, \
    LenField
from scapy.packet import Packet, bind_top_down


# USBpcap

_usbd_status_codes = {
    0x00000000: "Success",
    0x40000000: "Pending",
    0xC0000000: "Halted",
    0x80000000: "Error"
}

_transfer_types = {
    0x0: "Isochronous",
    0x1: "Interrupt",
    0x2: "Control"
}

# From https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-usb.c  # noqa: E501
_urb_functions = {
    0x0008: "URB_FUNCTION_CONTROL_TRANSFER",
    0x0009: "URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER",
    0x000A: "URB_FUNCTION_ISOCH_TRANSFER",
    0x000B: "URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE",
    0x000C: "URB_FUNCTION_SET_DESCRIPTOR_TO_DEVICE",
    0x000D: "URB_FUNCTION_SET_FEATURE_TO_DEVICE",
    0x000E: "URB_FUNCTION_SET_FEATURE_TO_INTERFACE",
    0x000F: "URB_FUNCTION_SET_FEATURE_TO_ENDPOINT",
    0x0010: "URB_FUNCTION_CLEAR_FEATURE_TO_DEVICE",
    0x0011: "URB_FUNCTION_CLEAR_FEATURE_TO_INTERFACE",
    0x0012: "URB_FUNCTION_CLEAR_FEATURE_TO_ENDPOINT",
    0x0013: "URB_FUNCTION_GET_STATUS_FROM_DEVICE",
    0x0014: "URB_FUNCTION_GET_STATUS_FROM_INTERFACE",
    0x0015: "URB_FUNCTION_GET_STATUS_FROM_ENDPOINT",
    0x0017: "URB_FUNCTION_VENDOR_DEVICE",
    0x0018: "URB_FUNCTION_VENDOR_INTERFACE",
    0x0019: "URB_FUNCTION_VENDOR_ENDPOINT",
    0x001A: "URB_FUNCTION_CLASS_DEVICE",
    0x001B: "URB_FUNCTION_CLASS_INTERFACE",
    0x001C: "URB_FUNCTION_CLASS_ENDPOINT",
    0x001F: "URB_FUNCTION_CLASS_OTHER",
    0x0020: "URB_FUNCTION_VENDOR_OTHER",
    0x0021: "URB_FUNCTION_GET_STATUS_FROM_OTHER",
    0x0022: "URB_FUNCTION_CLEAR_FEATURE_TO_OTHER",
    0x0023: "URB_FUNCTION_SET_FEATURE_TO_OTHER",
    0x0024: "URB_FUNCTION_GET_DESCRIPTOR_FROM_ENDPOINT",
    0x0025: "URB_FUNCTION_SET_DESCRIPTOR_TO_ENDPOINT",
    0x0026: "URB_FUNCTION_GET_CONFIGURATION",
    0x0027: "URB_FUNCTION_GET_INTERFACE",
    0x0028: "URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE",
    0x0029: "URB_FUNCTION_SET_DESCRIPTOR_TO_INTERFACE",
    0x002A: "URB_FUNCTION_GET_MS_FEATURE_DESCRIPTOR",
    0x0032: "URB_FUNCTION_CONTROL_TRANSFER_EX",
    0x0037: "URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER_USING_CHAINED_MDL",
    0x0002: "URB_FUNCTION_ABORT_PIPE",
    0x001E: "URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL",
    0x0030: "URB_FUNCTION_SYNC_RESET_PIPE",
    0x0031: "URB_FUNCTION_SYNC_CLEAR_STALL",
}


class USBpcap(Packet):
    name = "USBpcap URB"
    fields_desc = [ByteField("headerLen", None),
                   ByteField("res", 0),
                   XLELongField("irpId", 0),
                   LEIntEnumField("usbd_status", 0x0, _usbd_status_codes),
                   LEShortEnumField("function", 0, _urb_functions),
                   XByteField("info", 0),
                   LEShortField("bus", 0),
                   LEShortField("device", 0),
                   XByteField("endpoint", 0),
                   ByteEnumField("transfer", 0, _transfer_types),
                   LenField("dataLength", None, fmt="<I")]

    def post_build(self, p, pay):
        if self.headerLen is None:
            headerLen = len(p)
            if isinstance(self.payload, (USBpcapTransferIsochronous,
                                         USBpcapTransferInterrupt,
                                         USBpcapTransferControl)):
                headerLen += len(self.payload) - len(self.payload.payload)
            p = chb(headerLen) + p[1:]
        return p + pay

    def guess_payload_class(self, payload):
        if self.headerLen == 27:
            # No Transfer layer
            return super(USBpcap, self).guess_payload_class(payload)
        if self.transfer == 0:
            return USBpcapTransferIsochronous
        elif self.transfer == 1:
            return USBpcapTransferInterrupt
        elif self.transfer == 2:
            return USBpcapTransferControl
        return super(USBpcap, self).guess_payload_class(payload)


class USBpcapTransferIsochronous(Packet):
    name = "USBpcap Transfer Isochronous"
    fields_desc = [
        LEIntField("offset", 0),
        LEIntField("length", 0),
        LEIntEnumField("usbd_status", 0x0, _usbd_status_codes)
    ]


class USBpcapTransferInterrupt(Packet):
    name = "USBpcap Transfer Interrupt"
    fields_desc = [
        LEIntField("startFrame", 0),
        LEIntField("numberOfPackets", 0),
        LEIntField("errorCount", 0)
    ]


class USBpcapTransferControl(Packet):
    name = "USBpcap Transfer Control"
    fields_desc = [
        ByteField("stage", 0)
    ]


bind_top_down(USBpcap, USBpcapTransferIsochronous, transfer=0)
bind_top_down(USBpcap, USBpcapTransferInterrupt, transfer=1)
bind_top_down(USBpcap, USBpcapTransferControl, transfer=2)

conf.l2types.register(DLT_USBPCAP, USBpcap)
