# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

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

# Check platform arg

PLATFORM = None

if len(sys.argv) >= 2:
    if len(sys.argv) > 2:
        print("Usage: mypy_check.py [platform]")
        sys.exit(1)
    PLATFORM = sys.argv[1]

# Load files

localdir = os.path.split(__file__)[0]

with io.open(os.path.join(localdir, "mypy_enabled.txt")) as fd:
    FILES = [l.strip() for l in fd.readlines() if l.strip() and l[0] != "#"]

if not FILES:
    print("No files specified. Arborting")
    sys.exit(1)

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
    "--config-file=" + os.path.abspath(os.path.join(localdir, "mypy.ini")),
    "--show-traceback",
] + (["--platform=" + PLATFORM] if PLATFORM else [])

if PLATFORM.startswith("linux"):
    ARGS.extend(
        [
            "--always-true=LINUX",
            "--always-false=OPENBSD",
            "--always-false=FREEBSD",
            "--always-false=NETBSD",
            "--always-false=DARWIN",
            "--always-false=WINDOWS",
            "--always-false=BSD",
        ]
    )
    FILES = [x for x in FILES if not x.startswith("scapy/arch/windows")]
elif PLATFORM.startswith("win32"):
    ARGS.extend(
        [
            "--always-false=LINUX",
            "--always-false=OPENBSD",
            "--always-false=FREEBSD",
            "--always-false=NETBSD",
            "--always-false=DARWIN",
            "--always-true=WINDOWS",
            "--always-false=WINDOWS_XP",
            "--always-false=BSD",
        ]
    )
    FILES = [
        x
        for x in FILES
        if (
            x
            not in {
                # Disabled on Windows
                "scapy/arch/unix.py",
                "scapy/arch/solaris.py",
                "scapy/contrib/cansocket_native.py",
                "scapy/contrib/isotp/isotp_native_socket.py",
            }
        )
        and not x.startswith("scapy/arch/bpf")
        and not x.startswith("scapy/arch/linux")
    ]
else:
    raise ValueError("Unknown platform")

# Run mypy over the files
ARGS += [os.path.abspath(f) for f in FILES]

mypy_main(args=ARGS)
