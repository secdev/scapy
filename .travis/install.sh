# Install dependencies using pip
if [ -z $TRAVIS_SUDO ] && [ "$TRAVIS_OS_NAME" = "osx" ]
then 
  PIP_INSTALL_FLAGS="--user"
fi
$TRAVIS_SUDO pip install $PIP_INSTALL_FLAGS pycrypto mock

# Install pcap & dnet
if [ ! -z $SCAPY_USE_PCAPDNET ]
then
  if [ "$TRAVIS_OS_NAME" = "linux" ]
  then
    $TRAVIS_SUDO apt-get install python-pcapy python-dumbnet
  elif [ "$TRAVIS_OS_NAME" = "osx" ]
  then
    mkdir -p /Users/travis/Library/Python/2.7/lib/python/site-packages
    echo 'import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")' >> /Users/travis/Library/Python/2.7/lib/python/site-packages/homebrew.pth
 
    brew update
    brew install --with-python libdnet
    brew install .travis/pylibpcap.rb
  fi
fi
