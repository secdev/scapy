#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

RELEASE="9.0_2022Q2"
PACKAGES="git python27 python39 py39-virtualenv py27-sqlite3 py39-sqlite3 py39-expat rust mozilla-rootcerts-openssl"

sudo -s
unset PROMPT_COMMAND
export PATH="/sbin:/usr/pkg/sbin:/usr/pkg/bin:$PATH"
export PKG_PATH="http://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/amd64/${RELEASE}/All/"
pkg_delete curl
pkg_add -u $PACKAGES
git clone https://github.com/secdev/scapy
cd scapy
virtualenv-3.9 venv
. venv/bin/activate
pip install tox
chown -R vagrant:vagrant ../scapy/
