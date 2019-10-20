# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

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
