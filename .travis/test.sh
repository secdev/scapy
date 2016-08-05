# Dump Scapy config
python -c "from scapy.all import *; print conf"

# Don't run tests that requires root privileges
if [ -z $TRAVIS_SUDO ]
then
  UT_FLAGS="-K netaccess -K needs_root"
fi

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
  $TRAVIS_SUDO ./run_tests -q -F -t $f $UT_FLAGS -P "load_contrib('$(basename ${f/.uts})')" || exit $?
done
