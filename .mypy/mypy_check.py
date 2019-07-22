# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
Performs Static typing checks over Scapy's codebase
"""

import io
import os
import sys

from mypy.main import main as mypy_main

# Load files

with io.open("./.mypy/mypy_enabled.txt") as fd:
    FILES = [l.strip() for l in fd.readlines() if l.strip() and l[0] != "#"]

if not FILES:
    print("No files specified. Arborting")
    sys.exit(0)

# Generate Mypy arguments

ARGS = ["--py2"] + [os.path.abspath(f) for f in FILES]

# Run Mypy over the files

mypy_main(None, sys.stdout, sys.stderr, ARGS)
