# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Guillaume Valadon

import os
import sys

scapy_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(scapy_path)

from scapy.all import *

print("Scapy %s - Benchmarks" % VERSION)
print("Python %s" % sys.version.replace("\n", ""))
