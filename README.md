# Scapy #

[![Travis Build Status](https://travis-ci.org/secdev/scapy.svg?branch=master)](https://travis-ci.org/secdev/scapy)
[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/github/secdev/scapy?svg=true)](https://ci.appveyor.com/project/p-l-/scapy)
[![Codecov Status](https://codecov.io/gh/secdev/scapy/branch/master/graph/badge.svg)](https://codecov.io/gh/secdev/scapy)

Scapy is a powerful Python-based interactive packet manipulation
program and library.

It is able to forge or decode packets of a wide number of protocols,
send them on the wire, capture them, match requests and replies, and
much more.

It can easily handle most classical tasks like scanning, tracerouting,
probing, unit tests, attacks or network discovery (it can replace
hping, 85% of nmap, arpspoof, arp-sk, arping, tcpdump, tethereal, p0f,
etc.). It also performs very well at a lot of other specific tasks
that most other tools can't handle, like sending invalid frames,
injecting your own 802.11 frames, combining technics (VLAN hopping+ARP
cache poisoning, VOIP decoding on WEP encrypted channel, ...),
etc.

See
[interactive tutorial](http://scapy.readthedocs.io/en/latest/usage.html#interactive-tutorial)
and
[the quick demo: an interactive session](http://scapy.readthedocs.io/en/latest/introduction.html#quick-demo)
(some examples may be outdated).

# Contributing #

Want to contribute? Great! Please take a few minutes to
[read this](CONTRIBUTING.md)!

# License #

Scapy is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation, version 2.

Scapy is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
[along with Scapy](LICENSE). If not, see
[the gnu.org web site](http://www.gnu.org/licenses/).
