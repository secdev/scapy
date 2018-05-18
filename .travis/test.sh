if [ "$TRAVIS_OS_NAME" = "linux" ]
then
  # Linux
  UT_FLAGS=" -K tshark" # TODO: also test as root ?
  if [ "$TRAVIS_SUDO" != "true" ]
  then
    # Linux non root
    UT_FLAGS+=" -K manufdb"
  fi
  # pypy
  if python --version 2>&1 | grep -q PyPy
  then
    # cryptography requires PyPy >= 2.6, Travis CI uses 2.5.0
    UT_FLAGS+=" -K crypto -K not_pypy"
  fi
elif [ "$TRAVIS_OS_NAME" = "osx" ]
then
  UT_FLAGS=" -K tcpdump"
fi

if [[ $TOXENV == py3* ]]
then
  # Some Python 3 tests currently fail. They should be tracked and
  # fixed.
  UT_FLAGS+=" -K FIXME_py3"
fi

# Dump Environment (so that we can check PATH, UT_FLAGS, etc.)
set

tox -- $UT_FLAGS
