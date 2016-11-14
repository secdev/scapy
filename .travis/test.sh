# Dump Scapy config
python -c "from scapy.all import *; print conf"

# Don't run tests that require root privileges
if [ -z "$TRAVIS_SUDO" -o "$TRAVIS_SUDO" = "false" ]
then
  UT_FLAGS="-K netaccess "
  TRAVIS_SUDO=""
fi

# Test AEAD modes in IPSec if available
if [ "$TEST_COMBINED_MODES" != "yes" ]
then
  UT_FLAGS+="-K combined_modes "
fi

# Run unit tests
cd test/

for f in *.uts
do
  $TRAVIS_SUDO ./run_tests -f text -t $f $UT_FLAGS || exit $?
done

for f in ../scapy/contrib/*.uts
do
  $TRAVIS_SUDO ./run_tests -f text -t $f $UT_FLAGS -P "load_contrib('$(basename ${f/.uts})')" || exit $?
done
