# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
Generate MyPy deployment stats
"""

import os
import io
import glob
from collections import defaultdict

# Parse config file

localdir = os.path.split(__file__)[0]
rootpath = os.path.abspath(os.path.join(localdir, '../../'))

with io.open(os.path.join(localdir, "mypy_enabled.txt")) as fd:
    FILES = [l.strip() for l in fd.readlines() if l.strip() and l[0] != "#"]

# Scan Scapy

ALL_FILES = [
     "".join(x.partition("scapy/")[2:]) for x in
     glob.iglob(os.path.join(rootpath, 'scapy/**/*.py'), recursive=True)
]

# Process

REMAINING = defaultdict(list)
MODULES = defaultdict(lambda: (0, 0, 0, 0))

for f in ALL_FILES:
    with open(os.path.join(rootpath, f)) as fd:
        lines = len(fd.read().split("\n"))
    parts = f.split("/")
    if len(parts) > 2:
        mod = parts[1]
    else:
        mod = "[core]"
    e, l, t, a = MODULES[mod]
    if f in FILES:
        e += lines
        t += 1
    else:
        REMAINING[mod].append(f)
    l += lines
    a += 1
    MODULES[mod] = (e, l, t, a)

ENABLED = sum(x[0] for x in MODULES.values())
TOTAL = sum(x[1] for x in MODULES.values())

print("**MyPy Support: %.2f%%**" % (ENABLED / TOTAL * 100))
print("| Module | Typed code (lines) | Typed files |")
print("| --- | --- | --- |")
for mod, dat in MODULES.items():
    print("|`%s` | %.2f%% | %s/%s |" % (mod, dat[0] / dat[1] * 100, dat[2], dat[3]))

print()
COREMODS = REMAINING["[core]"]
if COREMODS:
    print("Core modules still untypes:")
    for mod in COREMODS:
        print("- `%s`" % mod)

