# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Nils Weiss <nils@we155.de>

# scapy.contrib.status = skip

"""
Package of contrib automotive modules that have to be loaded explicitly.
"""

import logging

log_automotive = logging.getLogger("scapy.contrib.automotive")

log_automotive.setLevel(logging.INFO)
