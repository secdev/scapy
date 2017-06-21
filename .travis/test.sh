# Dump environment variables
echo "SCAPY_SUDO=" $SCAPY_SUDO
echo "TRAVIS_OS_NAME=" $TRAVIS_OS_NAME

# Dump Scapy config
python -c "from scapy.all import *; print conf"

# Don't run tests that require root privileges
if [ -z "$SCAPY_SUDO" -o "$SCAPY_SUDO" = "false" ]
then
  UT_FLAGS="-K netaccess -K needs_root -K manufdb"
  SCAPY_SUDO=""
fi

# AES-CCM not implemented yet in Cryptography
# See
#  - https://github.com/pyca/cryptography/issues/2968
#  - https://github.com/pyca/cryptography/issues/1141
UT_FLAGS+=" -K combined_modes_ccm"

if python --version 2>&1 | grep -q PyPy
then
  # cryptography requires PyPy >= 2.6, Travis CI uses 2.5.0
  UT_FLAGS+=" -K crypto -K not_pypy"
fi

# Set PATH
for _path in /sbin /usr/sbin /usr/local/sbin; do
  [ -d "$_path" ] && echo "$PATH" | grep -qvE "(^|:)$_path(:|$)" && export PATH="$PATH:$_path"
done

# Create a fake Python executable
if [ "$SCAPY_COVERAGE" = "yes" ]
then
  echo '#!/bin/bash' > test/python
  echo '[ "$*" = "--version" ] && echo "Python 2 - fake version string"' >> test/python
  echo '[ "$*" != "--version" ] && coverage run --concurrency=multiprocessing -a $*' >> test/python
  chmod +x test/python
  PATH=.:$PATH

  # Copy the fake Python interpreter to bypass /etc/sudoers rules on Ubuntu
  if [ "$SCAPY_SUDO" = "sudo" ]
  then
    $SCAPY_SUDO cp test/python /usr/local/sbin/
  fi
fi

# Do we have tcpdump or thsark?
which tcpdump >/dev/null 2>&1 || UT_FLAGS+=" -K tcpdump"
which tshark >/dev/null 2>&1 || UT_FLAGS+=" -K tshark"

# Dump Environment (so that we can check PATH, UT_FLAGS, etc.)
set

# Run unit tests
cd test/

if [ "$TRAVIS_OS_NAME" = "osx" ]
then
  if [ -z $SCAPY_USE_PCAPDNET ]
  then
    $SCAPY_SUDO ./run_tests -q -F -t bpf.uts $UT_FLAGS || exit $?
  fi
  UT_FLAGS+=" -K manufdb -K linux"
else
  # IPv6 is not available yet on the linux machines (but is on OSX)
  UT_FLAGS+=" -K ipv6"
fi

# Run all normal and contrib tests
$SCAPY_SUDO ./run_tests -c ./configs/travis.utsc -T "bpf.uts" -T "mock_windows.uts" $UT_FLAGS || exit $?

# Run unit tests with openssl if we have root privileges
if [ "$TRAVIS_OS_NAME" = "linux" ] && [ ! -z $SCAPY_USE_PCAPDNET ] && [ ! -z $SCAPY_SUDO ]
then
  $SCAPY_SUDO ./run_tests -q -F -t tls/tests_tls_netaccess.uts $UT_FLAGS || exit $?
fi

