# Dump Scapy config
python -c "from scapy.all import *; print conf"

# Don't run tests that requires root privileges
if [ -z $TRAVIS_SUDO ]
then
  UT_FLAGS="-K netaccess "
fi

# Test AEAD modes in IPSec and TLS if available
if [ "$TEST_COMBINED_MODES" != "yes" ]
then
  UT_FLAGS+="-K combined_modes "
fi

# Run unit tests with UTscapy
cd test/

for f in *.uts
do
  $TRAVIS_SUDO ./run_tests -f text -t $f $UT_FLAGS || exit $?
done

for f in ../scapy/contrib/*.uts
do
  $TRAVIS_SUDO ./run_tests -f text -t $f $UT_FLAGS -P "load_contrib('$(basename ${f/.uts})')" || exit $?
done

# Run unit tests with openssl if we have root privileges
if [ "$TRAVIS_OS_NAME" = "linux" ] && [ ! -z $SCAPY_USE_PCAPDNET ] && [ ! -z $TRAVIS_SUDO ]
then
  $TRAVIS_SUDO ./run_tests_tls_netaccess || exit $?
fi

