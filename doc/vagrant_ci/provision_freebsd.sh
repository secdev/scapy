#!/usr/local/bin/bash

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

pkg update
pkg install --yes git python2 python3 py37-virtualenv py27-sqlite3 py37-sqlite3 bash rust
bash
git clone https://github.com/secdev/scapy
cd scapy
export PATH=/usr/local/bin/:$PATH
virtualenv-3.7 -p python3.7 venv
source venv/bin/activate
pip install tox
chown -R vagrant:vagrant /home/vagrant/scapy
