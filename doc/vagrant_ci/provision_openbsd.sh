#!/bin/bash

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

sudo pkg_add git python-2.7.15p0 python-3.6.6p1 py-virtualenv
sudo mkdir -p /usr/local/test/
sudo chown -R vagrant:vagrant /usr/local/test/
cd /usr/local/test/
git clone https://github.com/secdev/scapy
cd scapy
virtualenv venv
source venv/bin/activate
pip install tox
sudo chown -R vagrant:vagrant /usr/local/test/
