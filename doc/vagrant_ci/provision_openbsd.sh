#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

sudo pkg_add git python-2.7.18p0 python3 py-virtualenv
sudo mkdir -p /usr/local/test/
sudo chown -R vagrant:vagrant /usr/local/test/
cd /usr/local/test/
git clone https://github.com/secdev/scapy
cd scapy
virtualenv venv
source venv/bin/activate
pip install tox
sudo chown -R vagrant:vagrant /usr/local/test/
