#!/bin/bash

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

sudo -s
unset PROMPT_COMMAND
export PATH="/sbin:/usr/pkg/sbin:/usr/pkg/bin:$PATH"
export PKG_PATH="http://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/amd64/8.0_2018Q4/All/"
pkg_delete curl
pkg_add git python27 python36 py27-virtualenv py36-expat
git -c http.sslVerify=false clone https://github.com/secdev/scapy
cd scapy
virtualenv-2.7 venv
. venv/bin/activate
pip install tox
chown -R vagrant:vagrant ../scapy/
