<p align="center">
  <img src="doc/scapy_logo.png" width=200>
</p>

# Scapy #

[![Travis Build Status](https://travis-ci.org/secdev/scapy.svg?branch=master)](https://travis-ci.org/secdev/scapy)
[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/github/secdev/scapy?svg=true)](https://ci.appveyor.com/project/secdev/scapy)
[![Codecov Status](https://codecov.io/gh/secdev/scapy/branch/master/graph/badge.svg)](https://codecov.io/gh/secdev/scapy)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![Join the chat at https://gitter.im/secdev/scapy](https://badges.gitter.im/secdev/scapy.svg)](https://gitter.im/secdev/scapy?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)


Scapy is a powerful Python-based interactive packet manipulation program and
library.

It is able to forge or decode packets of a wide number of protocols, send them
on the wire, capture them, store or read them using pcap files, match requests
and replies, and much more. It is designed to allow fast packet prototyping by
using default values that work.

It can easily handle most classical tasks like scanning, tracerouting, probing,
unit tests, attacks or network discovery (it can replace `hping`, 85% of `nmap̀`,
`arpspoof`, `arp-sk`, `arping`, `tcpdump`, `wireshark`, `p0f`, etc.). It also
performs very well at a lot of other specific tasks that most other tools can't
handle, like sending invalid frames, injecting your own 802.11 frames, combining
techniques (VLAN hopping+ARP cache poisoning, VoIP decoding on WEP protected
channel, ...), etc.

Latest version of scapy now supports both Python 2.7 and Python 3. It's intended to
be cross platform, and supports many different platforms such as Linux, OSX, Windows...

## Hands-on ##

### Interactive shell ###

Scapy can easily be used as an interactive shell to interact with the network.
The following example shows how to send an ICMP Echo Request message to
`github.com`, then display the reply source IP address:

```python
sudo ./run_scapy 
Welcome to Scapy
>>> p = IP(dst="github.com")/ICMP()
>>> r = sr1(p)
Begin emission:
.Finished to send 1 packets.
*
Received 2 packets, got 1 answers, remaining 0 packets
>>> r[IP].src
'192.30.253.113'
```

### Python module ###

It is straightforward to use Scapy as a regular Python module, for example to
check if a TCP port is opened. First, save the following code in a file names
`send_tcp_syn.py`

```python
from scapy.all import *
conf.verb = 0

p = IP(dst="github.com")/TCP()
r = sr1(p)
print r.summary()
```

Then, launch the script with:
```python
sudo python send_tcp_syn.py
IP / TCP 192.30.253.113:http > 192.168.46.10:ftp_data SA / Padding
```

### [](#tutorials)Tutorials ###

To begin with Scapy, you should check [the notebook
hands-on](doc/notebooks/Scapy%20in%2015%20minutes.ipynb) and the [interactive
tutorial](http://scapy.readthedocs.io/en/latest/usage.html#interactive-tutorial).
If you want to learn more, see [the quick demo: an interactive
session](http://scapy.readthedocs.io/en/latest/introduction.html#quick-demo)
(some examples may be outdated), or play with the
[HTTP/2](doc/notebooks/HTTP_2_Tuto.ipynb) and [TLS](doc/notebooks/tls)
notebooks.


## Installation ##

Scapy works without any external Python modules on Linux and BSD like operating
systems. On Windows, you need to install some mandatory dependencies as
described in [the
documentation](http://scapy.readthedocs.io/en/latest/installation.html#windows).

On most systems, using Scapy is as simple as running the following commands:
```
git clone https://github.com/secdev/scapy
cd scapy
./run_scapy
>>>
```

To benefit from all Scapy features, such as plotting, you might want to install
Python modules, such as `matplotlib` or `cryptography`. See the
[documentation](http://scapy.readthedocs.io/en/latest/installation.html) and
follow the instructions to install them.


## Contributing ##

Want to contribute? Great! Please take a few minutes to
[read this](CONTRIBUTING.md)!
