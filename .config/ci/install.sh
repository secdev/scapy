#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# Install packages needed for the CI on Linux/MacOS
# Usage:
# ./install.sh [install mode]

# Detect install mode
if [[ "${1}" == "libpcap" ]]
then
    SCAPY_USE_LIBPCAP="yes"
    if [[ ! -z "$GITHUB_ACTIONS" ]]
    then
      echo "SCAPY_USE_LIBPCAP=yes" >> $GITHUB_ENV
    fi
fi

# Install on osx
if [ "${OSTYPE:0:6}" = "darwin" ]
then
  if [ ! -z $SCAPY_USE_LIBPCAP ]
  then
    brew update
    brew install libpcap
  fi
fi

CUR=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

# Install wireshark data, ifconfig, vcan, samba, openldap
if [ "$OSTYPE" = "linux-gnu" ]
then
  sudo apt-get update
  sudo apt-get -qy install tshark net-tools || exit 1
  sudo apt-get -qy install can-utils || exit 1
  sudo apt-get -qy install linux-modules-extra-$(uname -r) || exit 1
  sudo apt-get -qy install samba smbclient
  sudo bash $CUR/openldap/install.sh
  # Make sure libpcap is installed
  if [ ! -z $SCAPY_USE_LIBPCAP ]
  then
    sudo apt-get -qy install libpcap-dev  || exit 1
  fi
fi

# Update pip & setuptools (tox uses those)
python -m pip install --upgrade pip setuptools wheel --ignore-installed

# Make sure tox is installed and up to date
python -m pip install -U tox --ignore-installed

# Dump Environment (so that we can check PATH, UT_FLAGS, etc.)
set
