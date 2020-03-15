#!/bin/bash
# Install on osx
if [ "$OSTYPE" = "darwin"* ] || [ "$TRAVIS_OS_NAME" = "osx" ]
then
  if [ ! -z $SCAPY_USE_PCAPDNET ]
  then
    brew update
    brew install libdnet libpcap
  fi
fi

# Install wireshark data, ifconfig & vcan
if [ "$OSTYPE" = "linux-gnu" ] || [ "$TRAVIS_OS_NAME" = "linux" ]
then
  sudo apt-get update
  sudo apt-get -qy install tshark net-tools
  sudo apt-get -qy install can-utils build-essential linux-headers-$(uname -r) linux-modules-extra-$(uname -r);
fi

# Make sure libpcap is installed
if [ ! -z $SCAPY_USE_PCAPDNET ]
then
  $SCAPY_SUDO apt-get -qy install libpcap-dev
fi

# Update pip & setuptools (tox uses those)
python -m pip install --upgrade pip setuptools --ignore-installed

# Make sure tox is installed and up to date
python -m pip install -U tox --ignore-installed

# Dump Environment (so that we can check PATH, UT_FLAGS, etc.)
set
