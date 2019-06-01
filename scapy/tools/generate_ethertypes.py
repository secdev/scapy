# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""Generate the ethertypes file (/etc/ethertypes)
based on the OpenBSD source.

It allows to have a file with the format of
http://git.netfilter.org/ebtables/plain/ethertypes
but up-to-date.
"""

import re
import urllib.request

URL = "https://raw.githubusercontent.com/openbsd/src/master/sys/net/ethertypes.h"  # noqa: E501

with urllib.request.urlopen(URL) as stream:
    DATA = stream.read()

reg = rb".*ETHERTYPE_([^\s]+)\s.0x([0-9A-Fa-f]+).*\/\*(.*)\*\/"
COMPILED = b"""#
# Ethernet frame types
#       This file describes some of the various Ethernet
#       protocol types that are used on Ethernet networks.
#
# This list could be found on:
#         http://www.iana.org/assignments/ethernet-numbers
#         http://www.iana.org/assignments/ieee-802-numbers
#
# <name>    <hexnumber> <alias1>...<alias35> #Comment
#
"""
for line in DATA.split(b"\n"):
    match = re.match(reg, line)
    if match:
        name = match.group(1).ljust(16)
        number = match.group(2).upper()
        comment = match.group(3).strip()
        compiled_line = (b"%b%b" + b" " * 25 + b"# %b\n") % (
            name, number, comment
        )
        COMPILED += compiled_line

with open("ethertypes", "wb") as output:
    print("Written: %s" % output.write(COMPILED))
