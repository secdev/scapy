#!/bin/bash
# Install on osx
if [ "$TRAVIS_OS_NAME" = "osx" ]
then
  if [ ! -z $SCAPY_USE_PCAPDNET ]
  then
    brew update
    brew install libdnet libpcap
  fi
fi

# Install wireshark data
if [ "$TRAVIS_OS_NAME" = "linux" ] && [ "$TRAVIS_SUDO" = "true" ]
then
  sudo apt-get update
  sudo apt-get -qy install tshark
  sudo apt-get -qy install can-utils build-essential linux-headers-$(uname -r);
fi

# Install pcap & dnet
if [ ! -z $SCAPY_USE_PCAPDNET ] && [ "$TRAVIS_OS_NAME" = "linux" ]
then
  $SCAPY_SUDO apt-get -qy install libdumbnet-dev libpcap-dev
fi

# Update pip & setuptools (tox uses those)
python -m pip install --upgrade pip setuptools --ignore-installed

# Make sure tox is installed and up to date
python -m pip install -U tox --ignore-installed

# Dump Environment (so that we can check PATH, UT_FLAGS, etc.)
set
