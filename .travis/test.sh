# Report installed versions
echo "### INSTALLED VERSIONS ###"
python -c 'import sys; print("sys.path:" , sys.path)'
for DEPENDENCY in "six" "cryptography" "mock" "pcap" "dnet" "coverage"
do
  python -c 'import '$DEPENDENCY'; print("'$DEPENDENCY': "+str(getattr('$DEPENDENCY', "__version__", "no __version__ attribute")))'
  echo "----"
done

# Dump environment variables
echo "SCAPY_SUDO=" $SCAPY_SUDO
echo "TRAVIS_OS_NAME=" $TRAVIS_OS_NAME

# Dump Scapy config
python --version
python -c "from scapy.all import *; print(conf)"

# Don't run tests that require root privileges
if [ -z "$SCAPY_SUDO" -o "$SCAPY_SUDO" = "false" ]
then
  UT_FLAGS="-K netaccess -K needs_root -K manufdb"
  SCAPY_SUDO=""
else
  SCAPY_SUDO="$SCAPY_SUDO -H"
fi

if [ "$SCAPY_USE_PCAPDNET" = "yes" ]
then
  UT_FLAGS+=" -K not_pcapdnet"
fi
# IPv6 is not available yet on travis
UT_FLAGS+=" -K ipv6"

# AES-CCM, ChaCha20Poly1305 and X25519 were added to Cryptography v2.0
# but the minimal version mandated by scapy is v1.7
UT_FLAGS+=" -K crypto_advanced"

if python --version 2>&1 | grep -q PyPy
then
  # cryptography requires PyPy >= 2.6, Travis CI uses 2.5.0
  UT_FLAGS+=" -K crypto -K not_pypy"
fi

if python --version 2>&1 | grep -q '^Python 3\.'
then
  # Some Python 3 tests currently fail. They should be tracked and
  # fixed.
  UT_FLAGS+=" -K FIXME_py3"
fi

if python --version 2>&1 | grep -q '^Python 3\.[012345]'
then
  # Python 3 < 3.6 has weird behavior with random.seed()
  UT_FLAGS+=" -K random_weird_py3"
fi

if python --version 2>&1 | grep -q '^Python 3\.[0123]'
then
  # cryptography with Python 3 < 3.4 requires 3.3.7, Travis provides 3.3.6
  UT_FLAGS+=" -K crypto"
fi

# Set PATH
## /Users/travis/Library/Python/2.7/bin: pip when non-root on osx
for _path in /sbin /usr/sbin /usr/local/sbin /Users/travis/Library/Python/2.7/bin; do
  [ -d "$_path" ] && echo "$PATH" | grep -qvE "(^|:)$_path(:|$)" && export PATH="$PATH:$_path"
done

# Create a fake Python executable
if [ "$SCAPY_COVERAGE" = "yes" ]
then
  echo '#!/bin/bash' > test/python
  echo "[ \"\$*\" = \"--version\" ] && echo \"`python --version`\" && exit 0" >> test/python
  echo "`which coverage` run --rcfile=../.coveragerc --concurrency=multiprocessing -a \$*" >> test/python
  chmod +x test/python

  # Copy the fake Python interpreter to bypass /etc/sudoers rules on Ubuntu
  if [ -n "$SCAPY_SUDO" ]
  then
    $SCAPY_SUDO cp test/python /usr/local/sbin/
    PYTHON=/usr/local/sbin/python
  else
    PATH="`pwd`/test":$PATH
    PYTHON="`pwd`/test/python"
  fi
else
  PYTHON="`which python`"
fi

# Do we have tcpdump or thsark?
which tcpdump >/dev/null 2>&1 || UT_FLAGS+=" -K tcpdump"
which tshark >/dev/null 2>&1 || UT_FLAGS+=" -K tshark"

if [ -n "$SCAPY_SUDO" ]
then
  SCAPY_SUDO="$SCAPY_SUDO --preserve-env"
fi

# Dump Environment (so that we can check PATH, UT_FLAGS, etc.)
set

# Run unit tests
cd test/

if [ "$TRAVIS_OS_NAME" = "osx" ]
then
  if [ -z "$SCAPY_USE_PCAPDNET" ]
  then
    PYTHON="$PYTHON" $SCAPY_SUDO ./run_tests -q -F -t bpf.uts $UT_FLAGS || exit $?
  fi
  UT_FLAGS+=" -K manufdb -K linux"
fi

if [ "$TRAVIS_OS_NAME" = "linux" ]
then
  UT_FLAGS+=" -K osx"
fi

# Run all normal and contrib tests
PYTHON="$PYTHON" $SCAPY_SUDO ./run_tests -c ./configs/travis.utsc -T "bpf.uts" -T "mock_windows.uts" $UT_FLAGS || exit $?

# Run unit tests with openssl if we have root privileges
if [ "$TRAVIS_OS_NAME" = "linux" ] && [ -n "$SCAPY_SUDO" ]
then
  echo "Running TLS netaccess tests"
  PYTHON="$PYTHON" $SCAPY_SUDO ./run_tests -q -F -t tls/tests_tls_netaccess.uts $UT_FLAGS || exit $?
else
  echo "NOT running TLS netaccess tests"
fi

if [ "$SCAPY_COVERAGE" = "yes" ]; then
  coverage combine ./
  codecov
fi
