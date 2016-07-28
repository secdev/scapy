# Don't run tests that requires root privileges
if [ -z $TRAVIS_SUDO ]
then
  UT_FLAGS="-K netaccess"
fi

# Run unit tests
cd test/

for f in *.uts
do
  $TRAVIS_SUDO ./run_tests -q -F -t $f $UT_FLAGS || exit $?
done

for f in ../scapy/contrib/*.uts
do
  $TRAVIS_SUDO ./run_tests -q -F -t $f $UT_FLAGS -P "load_contrib('$(basename ${f/.uts})')" || exit $?
done
