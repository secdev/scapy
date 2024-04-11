# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
Generate the manuf.py file based on wireshark's manuf
"""

import gzip
import urllib.request

from base64 import b85encode

URL = "https://www.wireshark.org/download/automated/data/manuf"

with urllib.request.urlopen(URL) as stream:
    DATA = stream.read()

COMPILED = ""

for line in DATA.split(b"\n"):
    # We decode to strip any non-UTF8 characters.
    line = line.strip().decode("utf8", errors="backslashreplace")
    if not line or line.startswith("#"):
        continue
    COMPILED += line + "\n"

# Compress properly
COMPILED = gzip.compress(COMPILED.encode())
# Encode in Base85
COMPILED = b85encode(COMPILED).decode()
# Split
COMPILED = "\n".join(COMPILED[i : i + 79] for i in range(0, len(COMPILED), 79)) + "\n"


with open("../libs/manuf.py", "r") as inp:
    data = inp.read()

with open("../libs/manuf.py", "w") as out:
    ini, sep, _ = data.partition("DATA = _d(\"\"\"")
    COMPILED = ini + sep + "\n" + COMPILED + "\"\"\")\n"
    print("Written: %s" % out.write(COMPILED))
