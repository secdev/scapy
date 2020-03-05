# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
Scapy's post process of sphinx-api command
"""

import glob
import os
import sys

files = list(glob.iglob('./api/*.rst'))
parents = set(
    "%s.rst" % x for x in (
        f.rsplit('.', 1)[0] for f in (
            f[:-4] for f in files
        )
    ) if x
)

for f in files:
    # Post process each file
    _e = False
    with open(f) as fd:
        content = fd.readlines()
    if f in parents:
        # Process "parent files", i.e. with subfiles
        # Remove sub categories (better indexation)
        for name in ["Subpackages", "Submodules"]:
            try:
                sub = content.index(name+"\n")
            except ValueError:
                continue
            del content[sub:sub+3]
            _e = True
        # Custom
        if f.endswith("scapy.rst"):
            content[0] = "Scapy API reference\n"
            content[1] = "=" * (len(content[0]) - 1) + "\n"
            for i, line in enumerate(content):
                if "toctree" in line:
                    content[i] = line + "   :titlesonly:\n"
            _e = True
    # File / module file
    for name in ["package", "module"]:
        if name in content[0]:
            content[0] = content[0].replace(" " + name, "")
            content[1] = "=" * (len(content[0]) - 1) + "\n"
            _e = True
    if _e:
        print("Post-processed '%s'" % f)
        with open(f, "w") as fd:
            fd.writelines(content)
