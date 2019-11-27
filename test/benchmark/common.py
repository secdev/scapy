# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Guillaume Valadon
# This program is published under a GPLv2 license

import os
import sys

scapy_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(scapy_path)

from scapy.all import *

print("Scapy %s - Benchmarks" % VERSION)
print("Python %s" % sys.version.replace("\n", ""))
