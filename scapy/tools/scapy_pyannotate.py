# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Wrap Scapy's shell in pyannotate.
"""

import os
import sys
sys.path.insert(0, os.path.abspath('../../'))

from pyannotate_runtime import collect_types  # noqa: E402
from scapy.main import interact  # noqa: E402

collect_types.init_types_collection()
with collect_types.collect():
    interact()

collect_types.dump_stats("pyannotate_results_main")
