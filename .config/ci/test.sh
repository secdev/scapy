#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# test.sh
# Usage:
#   ./test.sh [tox version] [both/root/non_root (default root)]
# Examples:
#   ./test.sh 3.7 both
#   ./test.sh 3.9 non_root

if [ "$OSTYPE" = "linux-gnu" ]
then
  # Linux
  OSTOX="linux"
  UT_FLAGS+=" -K tshark"
  if [ -z "$SIMPLE_TESTS" ]
  then
    # check vcan
    sudo modprobe -n -v vcan
    if [[ $? -ne 0 ]]
    then
      # The vcan module is currently unavailable on xenial builds
      UT_FLAGS+=" -K vcan_socket"
    fi
  else
    UT_FLAGS+=" -K vcan_socket"
  fi
elif [[ "$OSTYPE" = "darwin"* ]] || [[ "$OSTYPE" = "FreeBSD" ]] || [[ "$OSTYPE" = *"bsd"* ]]
then
  OSTOX="bsd"
  # Travis CI in macOS 10.13+ can't load kexts. Need this for tuntaposx.
  UT_FLAGS+=" -K tun -K tap"
  if [[ "$OSTYPE" = "openbsd"* ]]
  then
    # Note: LibreSSL 3.6.* does not support X25519 according to
    # the cryptogaphy module source code
    UT_FLAGS+=" -K libressl"
  fi
fi

if [ ! -z "$GITHUB_ACTIONS" ]
then
  # Due to a security policy, the firewall of the Azure runner
  # (Standard_DS2_v2) that runs Github Actions on Linux blocks ICMP.
  UT_FLAGS+=" -K icmp_firewall"
fi

# pypy
if python --version 2>&1 | grep -q PyPy
then
  UT_FLAGS+=" -K not_pypy"
  # Code coverage with PyPy makes it very, very slow. Tests work
  # but take around 30minutes, so we disable it.
  export DISABLE_COVERAGE=" "
fi

# macos -k scanner has glitchy coverage. skip it
if [ "$OSTOX" = "bsd" ] && [[ "$UT_FLAGS" = *"-k scanner"* ]]; then
  export DISABLE_COVERAGE=" "
fi

# libpcap
if [[ ! -z "$SCAPY_USE_LIBPCAP" ]]; then
  UT_FLAGS+=" -K veth"
fi

# Create version tag (github actions)
PY_VERSION="py${1//./}"
PY_VERSION=${PY_VERSION/pypypy/pypy}
TESTVER="$PY_VERSION-$OSTOX"

# Chose whether to run root or non_root
SCAPY_TOX_CHOSEN=${2}
if [ "${SCAPY_TOX_CHOSEN}" == "" ]
then
  case ${PY_VERSION} in
    py27|py38)
      SCAPY_TOX_CHOSEN="both"
      ;;
    *)
      SCAPY_TOX_CHOSEN="root"
  esac
fi

if [ -z $TOXENV ]
then
  case ${SCAPY_TOX_CHOSEN} in
    both)
      export TOXENV="${TESTVER}-non_root,${TESTVER}-root"
      ;;
    root)
      export TOXENV="${TESTVER}-root"
      ;;
    *)
      export TOXENV="${TESTVER}-non_root"
      ;;
  esac
fi

# Configure OpenSSL
export OPENSSL_CONF=$(${PYTHON:=python} `dirname $BASH_SOURCE`/openssl.py)

# Dump vars (environment is already entirely dumped in install.sh)
echo OSTOX=$OSTOX
echo UT_FLAGS=$UT_FLAGS
echo TOXENV=$TOXENV
echo OPENSSL_CONF=$OPENSSL_CONF
echo OPENSSL_VER=$(openssl version)
echo COVERAGE=$([ -z "$DISABLE_COVERAGE" ] && echo "enabled" || echo "disabled")

if [ "$OSTYPE" = "linux-gnu" ]
then
  echo SMBCLIENT=$(smbclient -V)
fi

# Launch Scapy unit tests
TOX_PARALLEL_NO_SPINNER=1 tox -- ${UT_FLAGS} || exit 1

# Stop if NO_BASH_TESTS is set
if [ ! -z "$SIMPLE_TESTS" ]
then
  exit $?
fi

# Start Scapy in interactive mode
TEMPFILE=$(mktemp)
cat <<EOF > "${TEMPFILE}"
print("Scapy on %s" % sys.version)
sys.exit()
EOF
echo "DEBUG: TEMPFILE=${TEMPFILE}"
./run_scapy -H -c "${TEMPFILE}" || exit 1
