# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
[MS-RPCE] Remote Procedure Call Protocol Extensions

This module contains toolery to interact with Microsoft's [MS-RPCE]
(DCE/RPC) extensions.

It contains the following modules:

- ``scapy.layers.msrpce.rpcclient``: a MS-RPCE client
- ``scapy.layers.msrpce.rpcserver``: a MS-RPCE server
- ``scapy.layers.msrpce.ept``: DCE/RPC 1.1 endpoint mapper
- ``scapy.layers.msrpce.mspac``: [MS-PAC], the PAC in Kerberos packets
- ``scapy.layers.msrpce.msnrpc``: [MS-NRPC], a client and SSP
- ``scapy.layers.msnpce.raw``: raw RPC classes
"""
