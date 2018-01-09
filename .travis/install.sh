PIP=`which pip || (python --version 2>&1 | grep -q 'Python 2' && which pip2) || (python --version 2>&1 | grep -q 'Python 3' && which pip3)`

# Install dependencies using pip
if [ -z "$SCAPY_SUDO" -o "$SCAPY_SUDO" = "false" ]
then
  SCAPY_SUDO=""
  if [ "$TRAVIS_OS_NAME" = "osx" ]
  then
    PIP_INSTALL_FLAGS="--user"
  fi
else
  SCAPY_SUDO="$SCAPY_SUDO -H"
fi

$SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U mock

if python --version 2>&1 | grep -q '^Python 3\.[0123]'
then
  # cryptography with Python 3 < 3.4 requires enum34
  $SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U enum34
fi

if ! python --version 2>&1 | grep -q PyPy; then
  # cryptography requires PyPy >= 2.6, Travis CI uses 2.5.0
  $SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U cryptography
fi

# Install coverage
if [ "$SCAPY_COVERAGE" = "yes" ]
then
  $SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U coverage
  $SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U PyX
  $SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U codecov
fi

# Install pcap & dnet
if [ ! -z $SCAPY_USE_PCAPDNET ]
then
  if [ "$TRAVIS_OS_NAME" = "linux" ]
  then
    $SCAPY_SUDO apt-get -qy install libdumbnet-dev libpcap-dev
    # $SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U pypcap  ## sr(timeout) HS
    # $SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U pcapy   ## sniff HS
    # $SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U pylibpcap  ## won't install
    $SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U http://http.debian.net/debian/pool/main/p/python-libpcap/python-libpcap_0.6.4.orig.tar.gz
    $SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U pydumbnet
    # wget https://pypi.python.org/packages/71/60/15b9e0005bf9062bdc04fc8129b4cdb01cc4189a75719441ff2e23e55b15/dnet-real-1.12.tar.gz
    # tar zxf dnet-real-1.12.tar.gz
    # cd dnet-real-1.12
    # sed -i 's/dnet\.h/dumbnet.h/; s/|Py_TPFLAGS_CHECKTYPES//g' dnet.c
    # sed -i 's#dnet_extobj = \[\]#dnet_extobj = \["/usr/lib/libdumbnet.so"\]#' setup.py
    # $SCAPY_SUDO $PIP install $PIP_INSTALL_FLAGS -U .
    # cd ../
  elif [ "$TRAVIS_OS_NAME" = "osx" ]
  then
    mkdir -p /Users/travis/Library/Python/2.7/lib/python/site-packages
    echo 'import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")' >> /Users/travis/Library/Python/2.7/lib/python/site-packages/homebrew.pth
 
    brew update
    brew install --with-python libdnet
    brew install .travis/pylibpcap.rb
  fi
fi

# Install wireshark data
if [ ! -z "$SCAPY_SUDO" ] && [ "$TRAVIS_OS_NAME" = "linux" ]
then
  $SCAPY_SUDO apt-get -qy install openssl libwireshark-data
fi
