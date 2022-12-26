#!/usr/local/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

PACKAGES="git python2 python39 py39-virtualenv py39-pip py27-sqlite3 py39-sqlite3 bash rust sudo"

pkg update
pkg install --yes $PACKAGES
bash
git clone https://github.com/secdev/scapy
cd scapy
export PATH=/usr/local/bin/:$PATH
virtualenv-3.9 -p python3.9 venv
source venv/bin/activate
pip install tox
chown -R vagrant:vagrant /home/vagrant/scapy
