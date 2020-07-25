# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
Performs Static typing checks over Scapy's codebase
"""

# IMPORTANT NOTE
#
# Because we are rolling out mypy tests progressively,
# we currently use --follow-imports=skip. This means that
# mypy doesn't check consistency between the imports (different files).
#
# Once each file has been processed individually, we'll remove that to
# check the inconsistencies across the files

import io
import os
import sys

from mypy.main import main as mypy_main

# Load files

localdir = os.path.split(__file__)[0]

with io.open(os.path.join(localdir, "mypy_enabled.txt")) as fd:
    FILES = [l.strip() for l in fd.readlines() if l.strip() and l[0] != "#"]

if not FILES:
    print("No files specified. Arborting")
    sys.exit(0)

# Generate mypy arguments

ARGS = [
    # strictness: same as --strict minus --disallow-subclassing-any
    "--warn-unused-configs",
    "--disallow-any-generics",
    "--disallow-untyped-calls",
    "--disallow-untyped-defs",
    "--disallow-incomplete-defs",
    "--check-untyped-defs",
    "--disallow-untyped-decorators",
    "--no-implicit-optional",
    "--warn-redundant-casts",
    "--warn-unused-ignores",
    "--warn-return-any",
    "--no-implicit-reexport",
    "--strict-equality",
    "--ignore-missing-imports",
    # config
    "--follow-imports=skip",  # Remove eventually
    "--config-file=" + os.path.abspath(
        os.path.join(
            localdir,
            "mypy.ini"
        )
    ),
    "--show-traceback",
] + [os.path.abspath(f) for f in FILES]

# Run mypy over the files

mypy_main(None, sys.stdout, sys.stderr, ARGS)
