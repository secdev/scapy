#!/bin/bash

# test.sh
# Usage:
#   ./test.sh [tox version] [both/root/non_root (default root)]
# Examples:
#   ./test.sh 3.7 both
#   ./test.sh 3.9 non_root

if [ "$OSTYPE" = "linux-gnu" ] || [ "$TRAVIS_OS_NAME" = "linux" ]
then
  # Linux
  OSTOX="linux"
  UT_FLAGS+=" -K tshark"
  if [ ! -z "$GITHUB_ACTIONS" ]
  then
    # Due to a security policy, the firewall of the Azure runner
    # (Standard_DS2_v2) that runs Github Actions on Linux blocks ICMP.
    UT_FLAGS+=" -K icmp_firewall"
  fi
  if [ -z "$SIMPLE_TESTS" ]
  then
    # check vcan
    sudo modprobe -n -v vcan
    if [[ $? -ne 0 ]]
    then
      # The vcan module is currently unavailable on Travis-CI xenial builds
      UT_FLAGS+=" -K vcan_socket"
    fi
  else
    UT_FLAGS+=" -K vcan_socket"
  fi
elif [[ "$OSTYPE" = "darwin"* ]] || [ "$TRAVIS_OS_NAME" = "osx" ] || [[ "$OSTYPE" = "FreeBSD" ]]
then
  OSTOX="bsd"
  # Travis CI in macOS 10.13+ can't load kexts. Need this for tuntaposx.
  UT_FLAGS+=" -K tun -K tap"
fi

# pypy
if python --version 2>&1 | grep -q PyPy
then
  UT_FLAGS+=" -K not_pypy"
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
      export TOXENV="${TESTVER}_non_root,${TESTVER}_root"
      ;;
    root)
      export TOXENV="${TESTVER}_root"
      ;;
    *)
      export TOXENV="${TESTVER}_non_root"
      ;;
  esac
fi

# Configure OpenSSL
export OPENSSL_CONF=$($PYTHON `dirname $BASH_SOURCE`/openssl.py)

# Dump vars (the others were already dumped in install.sh)
echo UT_FLAGS=$UT_FLAGS
echo TOXENV=$TOXENV

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
