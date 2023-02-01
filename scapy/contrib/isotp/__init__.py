# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.description = ISO-TP (ISO 15765-2)
# scapy.contrib.status = loads

import logging

from scapy.consts import LINUX
from scapy.config import conf
from scapy.error import log_loading

from scapy.contrib.isotp.isotp_packet import ISOTP, ISOTPHeader, \
    ISOTPHeaderEA, ISOTP_SF, ISOTP_FF, ISOTP_CF, ISOTP_FC
from scapy.contrib.isotp.isotp_utils import ISOTPSession, \
    ISOTPMessageBuilder
from scapy.contrib.isotp.isotp_soft_socket import ISOTPSoftSocket
from scapy.contrib.isotp.isotp_scanner import isotp_scan

__all__ = ["ISOTP", "ISOTPHeader", "ISOTPHeaderEA", "ISOTP_SF", "ISOTP_FF",
           "ISOTP_CF", "ISOTP_FC", "ISOTPSoftSocket", "ISOTPSession",
           "ISOTPSocket", "ISOTPMessageBuilder", "isotp_scan",
           "USE_CAN_ISOTP_KERNEL_MODULE", "log_isotp"]

USE_CAN_ISOTP_KERNEL_MODULE = False

log_isotp = logging.getLogger("scapy.contrib.isotp")
log_isotp.setLevel(logging.INFO)

if LINUX:
    try:
        if conf.contribs['ISOTP']['use-can-isotp-kernel-module']:
            USE_CAN_ISOTP_KERNEL_MODULE = True
    except KeyError:
        log_loading.info(
            "Specify 'conf.contribs['ISOTP'] = {'use-can-isotp-kernel-module': True}' "  # noqa: E501
            "to enable usage of can-isotp kernel module.")

    from scapy.contrib.isotp.isotp_native_socket import ISOTPNativeSocket
    __all__.append("ISOTPNativeSocket")

if USE_CAN_ISOTP_KERNEL_MODULE:
    ISOTPSocket = ISOTPNativeSocket
else:
    ISOTPSocket = ISOTPSoftSocket
