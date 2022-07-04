# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
All layers. Configurable with conf.load_layers.
"""

from __future__ import absolute_import

# We import conf from arch to make sure arch specific layers are populated
from scapy.arch import conf
from scapy.error import log_loading
from scapy.main import load_layer

import logging
import scapy.libs.six as six

ignored = list(six.moves.builtins.__dict__) + ["sys"]
log = logging.getLogger("scapy.loading")

__all__ = []

for _l in conf.load_layers:
    log_loading.debug("Loading layer %s", _l)
    try:
        load_layer(_l, globals_dict=globals(), symb_list=__all__)
    except Exception as e:
        log.warning("can't import layer %s: %s", _l, e)

try:
    del _l
except NameError:
    pass
