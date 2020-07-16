#!/usr/local/bin/bash

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

pkg install --yes git python2 python3 py27-virtualenv py27-sqlite3 py37-sqlite3 bash
su - vagrant
bash
git clone https://github.com/secdev/scapy
cd scapy
export PATH=/usr/local/bin/:$PATH
virtualenv-2.7 -p python2.7 venv
source venv/bin/activate
pip install tox
sudo chown -R vagrant:vagrant /home/vagrant/scapy
