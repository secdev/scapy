# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
Generate the bluetoothids.py file based on blueooth_sig's public listing
"""

import yaml
import json
import gzip
import urllib.request

from base64 import b85encode

URL = "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml"  # noqa: E501

with urllib.request.urlopen(URL) as stream:
    DATA = yaml.safe_load(stream.read())

COMPILED = {}

for company in DATA["company_identifiers"]:
    COMPILED[company["value"]] = company["name"]

# Compress properly
COMPILED = gzip.compress(json.dumps(COMPILED).encode())
# Encode in Base85
COMPILED = b85encode(COMPILED).decode()
# Split
COMPILED = "\n".join(COMPILED[i : i + 79] for i in range(0, len(COMPILED), 79)) + "\n"


with open("../libs/bluetoothids.py", "r") as inp:
    data = inp.read()

with open("../libs/bluetoothids.py", "w") as out:
    ini, sep, _ = data.partition("DATA = _d(\"\"\"")
    COMPILED = ini + sep + "\n" + COMPILED + "\"\"\")\n"
    print("Written: %s" % out.write(COMPILED))
