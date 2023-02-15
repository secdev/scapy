# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
Default USB frames & Basic implementation
"""

# TODO: support USB headers for Darwin (netmon)
# https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-usb.c  # noqa: E501

import re
import subprocess
from enum import Enum, IntEnum

from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.compat import chb, plain_str
from scapy.data import DLT_USB_LINUX, DLT_USB_LINUX_MMAPPED, DLT_USBPCAP, MTU
from scapy.error import warning
from scapy.fields import ByteEnumField, ByteField, CharEnumField, \
    ConditionalField, EnumField, LEIntEnumField, LEIntField, LELongField, \
    LenField, LEShortEnumField, LEShortField, MultipleTypeField, \
    PacketLenField, StrLenField, XByteField, XLELongField
from scapy.interfaces import NetworkInterface, InterfaceProvider, \
    network_name, IFACES

from scapy.interfaces import IFACES, InterfaceProvider, NetworkInterface, network_name
from scapy.packet import Packet, bind_top_down
from scapy.supersocket import SuperSocket
from scapy.utils import PcapReader

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


def _extcap_call(prog, args, keyword, values):
    """Function used to call a program using the extcap format,
    then parse the results"""
    p = subprocess.Popen(
        [prog] + args,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    data, err = p.communicate()
    if p.returncode != 0:
        raise OSError("%s returned with error code %s: %s" % (prog,
                                                              p.returncode,
                                                              err))
    data = plain_str(data)
    res = []
    for ifa in data.split("\n"):
        ifa = ifa.strip()
        if not ifa.startswith(keyword):
            continue
        res.append(tuple([re.search(r"{%s=([^}]*)}" % val, ifa).group(1)
                          for val in values]))
    return res


if WINDOWS:
    def _usbpcap_check():
        if not conf.prog.usbpcapcmd:
            raise OSError("USBpcap is not installed ! (USBpcapCMD not found)")

    def get_usbpcap_interfaces():
        """Return a list of available USBpcap interfaces"""
        _usbpcap_check()
        return _extcap_call(
            conf.prog.usbpcapcmd,
            ["--extcap-interfaces"],
            "interface",
            ["value", "display"]
        )

    class UsbpcapInterfaceProvider(InterfaceProvider):
        name = "USBPcap"
        headers = ("Index", "Name", "Address")
        header_sort = 1

        def load(self):
            data = {}
            try:
                interfaces = get_usbpcap_interfaces()
            except OSError:
                return {}
            for netw_name, name in interfaces:
                index = re.search(r".*(\d+)", name)
                if index:
                    index = int(index.group(1)) + 100
                else:
                    index = 100
                if_data = {
                    "name": name,
                    "network_name": netw_name,
                    "description": name,
                    "index": index,
                }
                data[netw_name] = NetworkInterface(self, if_data)
            return data

        def l2socket(self):
            return conf.USBsocket
        l2listen = l2socket

        def l3socket(self):
            raise ValueError("No L3 available for USBpcap !")

        def _format(self, dev, **kwargs):
            """Returns a tuple of the elements used by show()"""
            return (str(dev.index), dev.name, dev.network_name)

    IFACES.register_provider(UsbpcapInterfaceProvider)

    def get_usbpcap_devices(iface, enabled=True):
        """Return a list of devices on an USBpcap interface"""
        _usbpcap_check()
        devices = _extcap_call(
            conf.prog.usbpcapcmd,
            ["--extcap-interface",
             iface,
             "--extcap-config"],
            "value",
            ["value", "display", "enabled"]
        )
        devices = [(dev[0],
                    dev[1],
                    dev[2] == "true") for dev in devices]
        if enabled:
            return [dev for dev in devices if dev[2]]
        return devices

    class USBpcapSocket(SuperSocket):
        """
        Read packets at layer 2 using USBPcapCMD
        """
        nonblocking_socket = True

        @staticmethod
        def select(sockets, remain=None):
            return sockets

        def __init__(self, iface=None, *args, **karg):
            _usbpcap_check()
            if iface is None:
                warning("Available interfaces: [%s]",
                        " ".join(x[0] for x in get_usbpcap_interfaces()))
                raise NameError("No interface specified !"
                                " See get_usbpcap_interfaces()")
            iface = network_name(iface)
            self.outs = None
            args = ['-d', iface, '-b', '134217728', '-A', '-o', '-']
            self.usbpcap_proc = subprocess.Popen(
                [conf.prog.usbpcapcmd] + args,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            self.ins = PcapReader(self.usbpcap_proc.stdout)

        def recv(self, x=MTU):
            return self.ins.recv(x)

        def close(self):
            SuperSocket.close(self)
            self.usbpcap_proc.kill()

    conf.USBsocket = USBpcapSocket


class EndpointNumber(ByteField):
    def any2i(self, pkt, x):
        if isinstance(x, tuple):
            return self.h2i(pkt, x)

        if isinstance(x, int):
            return x

        return super(EndpointNumber, self).any2i(pkt, x)

    def h2i(self, pkt, x):
        is_input, endpoint = x
        return endpoint | (int(is_input) << 7)

    def i2h(self, pkt, x):
        return bool(x >> 7), x & 0x7F

    def i2repr(self, pkt, val):
        is_input, endpoint = self.i2h(pkt, val)
        return "%s 0x%x" % (u"\u2190" if is_input else u"\u2192", endpoint)


# we have to do it since when using `PacketLenField`:
# `.parent` is not populated, so we cannot use `MultipleTypeField`
# alternatives are always evaluated no matter what
# no way to provide parameters even with severe perversions
setup_common_fields = [
    LEIntField("interval", None),
    LEIntField("start_frame", None),
    LEIntField("copy_of_urb_transfer_flags", None),
    LEIntField("iso_descriptors_count", None),
]


class SetupSetup(Packet):
    name = "Setup"

    class PcapUsbSetup(Packet):
        """USB setup header as defined in USB specification.
        Appears at the front of each Control S-type packet in DLT_USB captures.
        """

        name = "Setup"
        fields_desc = [
            XByteField("request_type", None),  # 1
            XByteField("request", None),  # 1
            LEShortField("value", None),  # 2
            LEShortField("index", None),  # 2
            LEShortField("length", None),  # 2
        ]

    fields_desc = [
        PacketLenField("s", None, PcapUsbSetup, length_from=lambda pkt: 8),
    ] + setup_common_fields


class SetupIsocr(Packet):
    name = "Setup"

    class IsoRec(Packet):
        """Information from the URB for Isochronous transfers.

        .. seealso::
        Source - https://github.com/the-tcpdump-group/libpcap/blob/ba0ef0353ed9f9f49a1edcfb49fefaf12dec54de/pcap/usb.h#L70
        """

        name = "IsoRec"
        fields_desc = [
            LEIntField("error_count", None),  # 4
            LEIntField("descriptors_count", None),  # 4
        ]

    fields_desc = [
        PacketLenField("s", None, IsoRec, length_from=lambda pkt: 8),
    ] + setup_common_fields


class USBMon(Packet):
    """A native pcap header of `usbmon <https://www.kernel.org/doc/Documentation/usb/usbmon.txt>`__ part of libpcap and Linux kernel.

    .. seealso::
    Source - https://github.com/the-tcpdump-group/libpcap/blob/ba0ef0353ed9f9f49a1edcfb49fefaf12dec54de/pcap/usb.h#L94


    .. seealso::
    Source - https://www.kernel.org/doc/Documentation/usb/usbmon.txt


    .. seealso::
    Source - https://www.kernel.org/doc/html/latest/driver-api/usb/URB.html


    .. seealso::
    Source - https://wiki.wireshark.org/USB
    """

    HEADER_SIZE = None
    name = "USBMonHeader"

    class EventType(Enum):
        completion = b"C"
        error = b"E"
        submit = b"S"

    class TransferType(IntEnum):
        isochronous = 0
        interrupt = 1
        control = 2
        bulk = 3

    class SetupFlag(Enum):
        relevant = b"\0"
        irrelevant = b"-"

    class DataFlag(Enum):
        urb = b"\0"
        incoming = b"<"
        outgoing = b">"
        error = b"E"

    class TimeStamp(Packet):
        name = "TimeStamp"

        @staticmethod
        def _getSize(*_args):
            return 12

        fields_desc = [
            LELongField("seconds", None),  # 8
            LEIntField("microseconds", None),  # 4
        ]

    @property
    def needs_setup(self):
        SetupFlag = self.__class__.SetupFlag
        return SetupFlag(self.setup_flag) == SetupFlag.relevant

    @property
    def is_isochr(self):
        TransferType = self.__class__.TransferType
        return TransferType(self.transfer_type) == TransferType.isochronous

    HEADER_STATIC_PART_SIZE = (
        8 + 1 + 1 + 1 + 1 + 2 + 1 + 1
        + TimeStamp._getSize() +  # pylint:disable=protected-access
        4 + 4 + 4
    )

    def _getOptionalPartSize(pkt=None):
        return 24

    def _getPaddingSize(pkt):
        res = pkt.__class__.HEADER_SIZE - __class__._getOptionalPartSize() * int(pkt.needs_setup) - __class__.HEADER_STATIC_PART_SIZE  # pylint:disable=protected-access
        return res

    fields_desc = [
        LELongField("urb_id", None),  # 8
        CharEnumField("event_type", b"\0", EventType),  # 1
        EnumField("transfer_type", 0, TransferType, "<B"),  # 1
        EndpointNumber("endpoint_number", 0),  # 1
        XByteField("device_address", None),  # 1
        LEShortField("bus_id", None),  # 2
        CharEnumField("setup_flag", b"\0", SetupFlag),  # 1
        CharEnumField("data_flag", b"\0", DataFlag),  # 1
        # just PacketField doesn't work and breaks everything after it
        PacketLenField("timestamp", None, TimeStamp, length_from=TimeStamp._getSize),  # 12, pylint:disable=protected-access
        LEIntEnumField("status", 0x0, _usbd_status_codes),  # 4
        LEIntField("urb_size", 0),  # 4
        LenField("data_size", 0, fmt="<i"),  # 4
        ConditionalField(
            MultipleTypeField(
                [
                    # just PacketField doesn't work and breaks everything after it
                    (PacketLenField("setup", None, SetupIsocr, length_from=_getOptionalPartSize), lambda pkt: pkt.is_isochr,),
                ],
                PacketLenField("setup", None, SetupSetup, length_from=_getOptionalPartSize),
            ),
            lambda pkt: pkt.needs_setup,
        ),  # 24
        StrLenField("padding", None, length_from=_getPaddingSize),
    ]


class USBMonSimple(USBMon):
    HEADER_SIZE = 48


class USBMonMMapped(USBMon):
    HEADER_SIZE = 64


conf.l2types.register(DLT_USB_LINUX, USBMonSimple)
conf.l2types.register(DLT_USB_LINUX_MMAPPED, USBMonMMapped)
