#!/bin/bash

# Usage:
# ./install.sh [install mode]

# Detect install mode
if [[ "${1}" == "libpcap" ]]; then
    SCAPY_USE_LIBPCAP="yes"
    if [[ ! -z "$GITHUB_ACTIONS" ]]; then
      echo "SCAPY_USE_LIBPCAP=yes" >> $GITHUB_ENV
    fi
fi

# Install on osx
if [ "$OSTYPE" = "darwin"* ] || [ "$TRAVIS_OS_NAME" = "osx" ]
then
  if [ ! -z $SCAPY_USE_LIBPCAP ]
  then
    brew update
    brew install libpcap
  fi
fi

# Install wireshark data, ifconfig & vcan
if [ "$OSTYPE" = "linux-gnu" ] || [ "$TRAVIS_OS_NAME" = "linux" ]
then
  sudo apt-get update
  sudo apt-get -qy install tshark net-tools || exit 1
  sudo apt-get -qy install can-utils build-essential linux-headers-$(uname -r) linux-modules-extra-$(uname -r) || exit 1
fi

# Make sure libpcap is installed
if [ ! -z $SCAPY_USE_LIBPCAP ]
then
  sudo apt-get -qy install libpcap-dev  || exit 1
fi

# On Travis, "osx" dependencies are installed in .travis.yml
if [ "$TRAVIS_OS_NAME" != "osx" ]
then
  # Update pip & setuptools (tox uses those)
  python -m pip install --upgrade pip setuptools --ignore-installed

  # Make sure tox is installed and up to date
  python -m pip install -U tox --ignore-installed
fi

# Dump Environment (so that we can check PATH, UT_FLAGS, etc.)
openssl version
set
