# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
[QUIC] Tools for handling QUIC packets and sessions.

TODO:
- Rework organization of QUIC layers. (e.g., layers for QUIC packet, QUIC payload, QUIC frame, etc.)
- Implement cryptographic features for QUIC, including initial encryption contexts based on QUIC Version.
- Implement automaton for Handshake, sessions, etc.
- And more...
"""