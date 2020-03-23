#!/bin/bash

# test.sh
# Usage:
#   ./test.sh [tox version] [both/root/non_root (default root)]
# Example:
#   ./test.sh 3.7 both

if [ "$OSTYPE" = "linux-gnu" ] || [ "$TRAVIS_OS_NAME" = "linux" ]
then
  # Linux
  OSTOX="linux"
  UT_FLAGS=" -K tshark" # TODO: also test as root ?
  # check vcan
  sudo modprobe -n -v vcan
  if [[ $? -ne 0 ]]
  then
    # The vcan module is currently unavailable on Travis-CI xenial builds
    UT_FLAGS+=" -K vcan_socket"
  fi
elif [ "$OSTYPE" = "darwin"* ] || [ "$TRAVIS_OS_NAME" = "osx" ]
then
  OSTOX="osx"
  UT_FLAGS=" -K tcpdump"
fi

# pypy
if python --version 2>&1 | grep -q PyPy
then
  UT_FLAGS+=" -K not_pypy"
fi

# Create version tag (github actions)
PY_VERSION="py${1//./}"
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
      TOXENV="${TESTVER}_non_root,${TESTVER}_root"
      ;;
    root)
      TOXENV="${TESTVER}_root"
      ;;
    *)
      TOXENV="${TESTVER}_non_root"
      ;;
  esac
fi

# Dump vars (the others were already dumped in install.sh)
echo UT_FLAGS=$UT_FLAGS
echo TOXENV=$TOXENV

# Launch Scapy unit tests
tox -- ${UT_FLAGS}

# Start Scapy in interactive mode
TEMPFILE=$(mktemp)
cat << EOF > ${TEMPFILE}
print("Scapy on %s" % sys.version)
sys.exit()
EOF
./run_scapy -H -c ${TEMPFILE}
rm ${TEMPFILE}
