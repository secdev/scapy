# Dump environment variables
echo "TRAVIS_SUDO=" $TRAVIS_SUDO
echo "TRAVIS_OS_NAME=" $TRAVIS_OS_NAME

# Dump Scapy config
python -c "from scapy.all import *; print conf"

# Don't run tests that require root privileges
if [ -z "$TRAVIS_SUDO" -o "$TRAVIS_SUDO" = "false" ]
then
  UT_FLAGS="-K netaccess -K needs_root"
  TRAVIS_SUDO=""
fi

# Test AEAD modes in IPsec if available
if [ "$TEST_COMBINED_MODES" != "yes" ]
then
  UT_FLAGS+=" -K combined_modes"
fi

# Set PATH
for _path in /sbin /usr/sbin /usr/local/sbin; do
  [ -d "$_path" ] && echo "$PATH" | grep -qvE "(^|:)$_path(:|$)" && export PATH="$PATH:$_path"
done

# Do we have tcpdump?
which tcpdump >/dev/null 2>&1 || UT_FLAGS+=" -K tcpdump"

# Dump Environment (so that we can check PATH, UT_FLAGS, etc.)
set

# Run unit tests
cd test/

if [ "$TRAVIS_OS_NAME" = "osx" ]
then
  if [ -z $SCAPY_USE_PCAPDNET ]
  then
    $TRAVIS_SUDO ./run_tests -q -F -t bpf.uts $UT_FLAGS || exit $?
  fi
fi

for f in *.uts
do
  if [ "$f" = "bpf.uts" ]
  then
    continue
  fi
  $TRAVIS_SUDO ./run_tests -q -F -t $f $UT_FLAGS || exit $?
done

for f in ../scapy/contrib/*.uts
do
  $TRAVIS_SUDO ./run_tests -f text -t $f $UT_FLAGS -P "load_contrib('$(basename ${f/.uts})')" || exit $?
done
