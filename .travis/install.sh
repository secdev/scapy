# Install dependencies using pip
if [ -z "$SCAPY_SUDO" -o "$SCAPY_SUDO" = "false" ]; then
  SCAPY_SUDO=""
  if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    PIP_INSTALL_FLAGS="--user"
  fi
fi

if python --version 2>&1 | grep -q PyPy; then
  # cryptography requires PyPy >= 2.6, Travis CI uses 2.5.0
  pip install mock netifaces
else
  pip install --upgrade cryptography mock netifaces six coverage
fi

# Install pcap & dnet
if [ ! -z $SCAPY_USE_PCAPDNET ]; then
  if [ "$TRAVIS_OS_NAME" = "linux" ]; then
    pip install pcapy
    git clone https://github.com/dugsong/libdnet.git
    pushd libdnet && ./configure && make
    cd python && pip install . && popd
  elif [ "$TRAVIS_OS_NAME" = "osx" ]; then
    mkdir -p /Users/travis/Library/Python/2.7/lib/python/site-packages
    echo 'import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")' >> /Users/travis/Library/Python/2.7/lib/python/site-packages/homebrew.pth
 
    brew install libdnet .travis/pylibpcap.rb
  fi
fi
