# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""Generate the ethertypes file (/etc/ethertypes) based on the OpenBSD source
https://github.com/openbsd/src/blob/master/sys/net/ethertypes.h

It allows to have a file with the format of
http://git.netfilter.org/ebtables/plain/ethertypes
but up-to-date.
"""

import gzip
import re
import urllib.request

from base64 import b85encode
from scapy.error import log_loading

URL = "https://raw.githubusercontent.com/openbsd/src/master/sys/net/ethertypes.h"  # noqa: E501

with urllib.request.urlopen(URL) as stream:
    DATA = stream.read()

reg = r".*ETHERTYPE_([^\s]+)\s.0x([0-9A-Fa-f]+).*\/\*(.*)\*\/"
COMPILED = """#
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
ALIASES = {"IP": "IPv4", "IPV6": "IPv6"}

for line in DATA.split(b"\n"):
    try:
        match = re.match(reg, line.decode("utf8", errors="backslashreplace"))
        if match:
            name = match.group(1)
            name = ALIASES.get(name, name).ljust(16)
            number = match.group(2).upper()
            comment = match.group(3).strip()
            COMPILED += ("%s%s" + " " * 25 + "# %s\n") % (name, number, comment)
    except Exception:
        log_loading.warning(
            "Couldn't parse one line from [%s] [%r]", URL, line, exc_info=True
        )

# Compress properly
COMPILED = gzip.compress(COMPILED.encode())
# Encode in Base85
COMPILED = b85encode(COMPILED).decode()
# Split
COMPILED = "\n".join(COMPILED[i : i + 79] for i in range(0, len(COMPILED), 79)) + "\n"

with open("../libs/ethertypes.py", "r") as inp:
    data = inp.read()

with open("../libs/ethertypes.py", "w") as out:
    ini, sep, _ = data.partition("DATA = _d(\"\"\"")
    COMPILED = ini + sep + "\n" + COMPILED + "\"\"\")\n"
    print("Written: %s" % out.write(COMPILED))
