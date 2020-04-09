# This file is part of Scapy
# See https://scapy.net for more information
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
Generate MyPy deployment stats
"""

import os
import io
import glob
from collections import defaultdict

# Parse config file

localdir = os.path.split(__file__)[0]

with io.open(os.path.join(localdir, "mypy_enabled.txt")) as fd:
    FILES = [l.strip() for l in fd.readlines() if l.strip() and l[0] != "#"]

# Scan Scapy

ALL_FILES = [
     "".join(x.partition("scapy/")[1:]) for x in
     glob.iglob('../../scapy/**/*.py', recursive=True)
]

# Process

TOTAL = len(ALL_FILES)
ENABLED = 0
MODULES = defaultdict(lambda: (0, []))

for f in ALL_FILES:
    parts = f.split("/")
    if len(parts) > 2:
        mod = parts[1]
    else:
        mod = "[main]"
    e, l = MODULES[mod]
    if f in FILES:
        ENABLED += 1
        e += 1
    l.append(f)
    MODULES[mod] = (e, l)

print("*The numbers correspond to the amount of files processed*")
print("**MyPy Support: %.2f%%**" % (ENABLED / TOTAL * 100))
for mod, dat in MODULES.items():
    print("- `%s`: %.2f%%" % (mod, dat[0] / len(dat[1]) * 100))
