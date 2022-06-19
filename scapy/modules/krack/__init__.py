# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""Module implementing Krack Attack on client, as a custom WPA Access Point

Requires the python cryptography package v1.7+. See https://cryptography.io/

More details on the attack can be found on https://www.krackattacks.com/

Example of use (from the scapy shell):
>>> load_module("krack")
>>> KrackAP(
    iface="mon0",               # A monitor interface
    ap_mac='11:22:33:44:55:66', # MAC (BSSID) to use
    ssid="TEST_KRACK",          # SSID
    passphrase="testtest",      # Associated passphrase
).run()

Then, on the target device, connect to "TEST_KRACK" using "testtest" as the
passphrase.
The output logs will indicate if one of the vulnerability have been triggered.

Outputs for vulnerable devices:
- IV re-use!! Client seems to be vulnerable to handshake 3/4 replay
  (CVE-2017-13077)
- Broadcast packet accepted twice!! (CVE-2017-13080)
- Client has installed an all zero encryption key (TK)!!

For patched devices:
- Client is likely not vulnerable to CVE-2017-13080
"""

from scapy.config import conf

if conf.crypto_valid:
    from scapy.modules.krack.automaton import KrackAP  # noqa: F401
else:
    raise ImportError("Cannot import Krack module due to missing dependency. "
                      "Please install python{3}-cryptography v1.7+.")
