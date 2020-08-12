# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

import os
import pytest  # noqa: F401

import scapy.modules.six as six
from scapy.config import conf


def pytest_addoption(parser):
    parser.addoption("-K", action='append', nargs="*")


def pytest_configure(config):
    try:
        KW_KO = config.getoption("-K") or []

        if six.PY2:
            KW_KO.append(["python3_only"])

        try:
            if os.getuid() != 0:
                KW_KO.append(["netaccess"])
                KW_KO.append(["needs_root"])
        except AttributeError:
            pass

        if conf.use_pcap:
            KW_KO.append(["not_pcapdnet"])

        if six.PY3:
            KW_KO.append(["FIXME_py3"])

        if len(config.option.markexpr) and len(KW_KO):
            config.option.markexpr += " and "

        config.option.markexpr += "not " + " and not ".join(
            [x[0] for x in KW_KO])
    except TypeError:
        pass
