# Install dependencies using pip
if [ -z "$SCAPY_SUDO" -o "$SCAPY_SUDO" = "false" ]
then
  SCAPY_SUDO=""
  if [ "$TRAVIS_OS_NAME" = "osx" ]
  then
    PIP_INSTALL_FLAGS="--user"
  fi
fi

if python --version 2>&1 | grep -q PyPy; then
  wget https://pypi.python.org/packages/82/f7/d6dfd7595910a20a563a83a762bf79a253c4df71759c3b228accb3d7e5e4/cryptography-1.7.1.tar.gz
  tar zxf cryptography-1.7.1.tar.gz
  cd cryptography-1.7.1
  patch << EOF
--- setup.py
+++ setup.py
@@ -47,7 +47,7 @@ if sys.version_info < (3, 4):
 if sys.version_info < (3, 3):
     requirements.append("ipaddress")
 
-if platform.python_implementation() == "PyPy":
+if False:
     if sys.pypy_version_info < (2, 6):
         raise RuntimeError(
             "cryptography 1.0 is not compatible with PyPy < 2.6. Please "
EOF
  $SCAPY_SUDO pip install $PIP_INSTALL_FLAGS .
  cd ../
  rm -rf cryptography-*
  $SCAPY_SUDO pip install $PIP_INSTALL_FLAGS ecdsa mock
else
  $SCAPY_SUDO pip install $PIP_INSTALL_FLAGS cryptography ecdsa mock
fi

# Install coverage
if [ "$SCAPY_COVERAGE" = "yes" ]
then
  $SCAPY_SUDO pip install $PIP_INSTALL_FLAGS coverage
fi

# Install pcap & dnet
if [ ! -z $SCAPY_USE_PCAPDNET ]
then
  if [ "$TRAVIS_OS_NAME" = "linux" ]
  then
    $SCAPY_SUDO apt-get install python-libpcap python-dumbnet
  elif [ "$TRAVIS_OS_NAME" = "osx" ]
  then
    mkdir -p /Users/travis/Library/Python/2.7/lib/python/site-packages
    echo 'import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")' >> /Users/travis/Library/Python/2.7/lib/python/site-packages/homebrew.pth
 
    brew update
    brew install --with-python libdnet
    brew install .travis/pylibpcap.rb
  fi
fi
