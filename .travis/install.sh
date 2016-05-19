# Install dependencies using pip
if [ -z $TRAVIS_SUDO ] && [ "$TRAVIS_OS_NAME" = "osx" ]
then 
  PIP_INSTALL_FLAGS="--user"
fi
$TRAVIS_SUDO pip install $PIP_INSTALL_FLAGS pycrypto mock

# Install pcap & dnet
if [ ! -z $SCAPY_USE_PCAPDNET ]
then
  $TRAVIS_SUDO apt-get install python-pcapy python-dumbnet
fi
