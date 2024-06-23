#!/usr/bin/python3

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

import sys
import atheris

with atheris.instrument_imports():
    import io
    import scapy
    import scapy.error
    import scapy.layers.all
    import scapy.utils


def TestOneInput(input_bytes):
    try:
        for p in scapy.utils.rdpcap(io.BytesIO(input_bytes)):
            p.summary()
    except scapy.error.Scapy_Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
