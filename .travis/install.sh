# Install dependencies using pip
if [ -z "$TRAVIS_SUDO" -o "$TRAVIS_SUDO" = "false" ]
then
  TRAVIS_SUDO=""
  if [ "$TRAVIS_OS_NAME" = "osx" ]
  then
    PIP_INSTALL_FLAGS="--user"
  fi
fi
$TRAVIS_SUDO pip install $PIP_INSTALL_FLAGS ecdsa mock

# Pycrypto 2.7a1 isn't available on PyPi
if [ "$TEST_COMBINED_MODES" = "yes" ]
then
  curl -sL https://github.com/dlitz/pycrypto/archive/v2.7a1.tar.gz | tar xz
  cd pycrypto-2.7a1
  python setup.py build
  $TRAVIS_SUDO python setup.py install
else
  $TRAVIS_SUDO pip install $PIP_INSTALL_FLAGS pycrypto
fi

# Install pcap & dnet
if [ ! -z $SCAPY_USE_PCAPDNET ]
then
  if [ "$TRAVIS_OS_NAME" = "linux" ]
  then
    $TRAVIS_SUDO apt-get install python-libpcap python-dumbnet
  elif [ "$TRAVIS_OS_NAME" = "osx" ]
  then
    mkdir -p /Users/travis/Library/Python/2.7/lib/python/site-packages
    echo 'import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")' >> /Users/travis/Library/Python/2.7/lib/python/site-packages/homebrew.pth
 
    brew update
    brew install --with-python libdnet
    brew install .travis/pylibpcap.rb
  fi
fi
