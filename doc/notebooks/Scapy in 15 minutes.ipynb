{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# Scapy in 15 minutes (or longer)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "##### Guillaume Valadon & Pierre Lalet"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "[Scapy](http://www.secdev.org/projects/scapy) is a powerful Python-based interactive packet manipulation program and library. It can be used to forge or decode packets for a wide number of protocols, send them on the wire, capture them, match requests and replies, and much more.\n",
    "\n",
    "This iPython notebook provides a short tour of the main Scapy features. It assumes that you are familiar with networking terminology. All examples were built using the development version from [https://github.com/secdev/scapy](https://github.com/secdev/scapy), and tested on Linux. They should work as well on OS X, and other BSD.\n",
    "\n",
    "The current documentation is available on [http://scapy.readthedocs.io/](http://scapy.readthedocs.io/) !"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Scapy eases network packets manipulation, and allows you to forge complicated packets to perform advanced tests. As a teaser, let's have a look a two examples that are difficult to express without Scapy:\n",
    "\n",
    "1_ Sending a TCP segment with maximum segment size set to 0 to a specific port is an interesting test to perform against embedded TCP stacks. It can be achieved with the following one-liner:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 30,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "\n",
      "Sent 1 packets.\n"
     ]
    }
   ],
   "source": [
    "send(IP(dst=\"1.2.3.4\")/TCP(dport=502, options=[(\"MSS\", 0)]))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "2_ Advanced firewalking using IP options is sometimes useful to perform network enumeration. Here is a more complicated one-liner:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 31,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "  -                            IPOption_RR                  IPOption_Traceroute          \n",
      "1 192.168.42.1 time-exceeded 192.168.46.1 time-exceeded 192.168.46.1 time-exceeded \n",
      "2 172.42.0.1 time-exceeded     172.42.0.1 time-exceeded     172.42.0.1 time-exceeded     \n",
      "3 42.10.69.251 time-exceeded  42.10.69.251 time-exceeded  42.10.69.251 time-exceeded  \n",
      "4 10.123.156.86 time-exceeded  10.123.156.86 time-exceeded  -                            \n",
      "5 69.156.98.177 time-exceeded 69.156.98.177 time-exceeded -                            \n",
      "6 69.156.137.74 time-exceeded 69.156.137.74 time-exceeded -                            \n",
      "7 209.85.172.150 time-exceeded -                            -                            \n",
      "8 216.239.57.203 time-exceeded -                            -                            \n"
     ]
    }
   ],
   "source": [
    "ans = sr([IP(dst=\"8.8.8.8\", ttl=(1, 8), options=IPOption_RR())/ICMP(seq=RandShort()), IP(dst=\"8.8.8.8\", ttl=(1, 8), options=IPOption_Traceroute())/ICMP(seq=RandShort()), IP(dst=\"8.8.8.8\", ttl=(1, 8))/ICMP(seq=RandShort())], verbose=False, timeout=3)[0]\n",
    "ans.make_table(lambda x, y: (\", \".join(z.summary() for z in x[IP].options) or '-', x[IP].ttl, y.sprintf(\"%IP.src% %ICMP.type%\")))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "#### Now that we've got your attention, let's start the tutorial !"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Quick setup"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "The easiest way to try Scapy is to clone the github repository, then launch the `run_scapy` script as root. The following examples can be pasted at the Scapy prompt. There is no need to install any external Python modules."
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "```shell\n",
    "git clone https://github.com/secdev/scapy --depth=1\n",
    "sudo ./run_scapy\n",
    "Welcome to Scapy (2.4.0)\n",
    ">>>\n",
    "```"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Note: iPython users must import scapy as follows"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 13,
   "metadata": {},
   "outputs": [],
   "source": [
    "from scapy.all import *"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## First steps"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "With Scapy, each network layer is a Python class.\n",
    "\n",
    "The `'/'` operator is used to bind layers together. Let's put a TCP segment on top of IP and assign it to the `packet` variable, then stack it on top of Ethernet. "
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 2,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  |>>>"
      ]
     },
     "execution_count": 2,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "packet = IP()/TCP()\n",
    "Ether()/packet"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "This last output displays the packet summary. Here, Scapy automatically filled the Ethernet type as well as the IP protocol field.\n",
    "\n",
    "Protocol fields can be listed using the `ls()` function:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "    >>> ls(IP, verbose=True)\n",
    "    version    : BitField (4 bits)                   = (4)\n",
    "    ihl        : BitField (4 bits)                   = (None)\n",
    "    tos        : XByteField                          = (0)\n",
    "    len        : ShortField                          = (None)\n",
    "    id         : ShortField                          = (1)\n",
    "    flags      : FlagsField (3 bits)                 = (0)\n",
    "                   MF, DF, evil\n",
    "    frag       : BitField (13 bits)                  = (0)\n",
    "    ttl        : ByteField                           = (64)\n",
    "    proto      : ByteEnumField                       = (0)\n",
    "    chksum     : XShortField                         = (None)\n",
    "    src        : SourceIPField (Emph)                = (None)\n",
    "    dst        : DestIPField (Emph)                  = (None)\n",
    "    options    : PacketListField                     = ([])"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Let's create a new packet to a specific IP destination. With Scapy, each protocol field can be specified. As shown in the `ls()` output, the interesting field is `dst`.\n",
    "\n",
    "Scapy packets are objects with some useful methods, such as `summary()`."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 3,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "text/plain": [
       "\"Ether / IP / TCP 172.20.10.2:ftp_data > Net('www.secdev.org'):http S\""
      ]
     },
     "execution_count": 3,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "p = Ether()/IP(dst=\"www.secdev.org\")/TCP()\n",
    "p.summary()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "There are not many differences with the previous example. However, Scapy used the specific destination to perform some magic tricks !\n",
    "\n",
    "Using internal mechanisms (such as DNS resolution, routing table and ARP resolution), Scapy has automatically set fields necessary to send the packet. These fields can of course be accessed and displayed."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 10,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "3a:71:de:90:0b:64\n",
      "172.20.10.2\n",
      "b8:e8:56:45:8c:e6 > 3a:71:de:90:0b:64\n",
      "172.20.10.2 > Net('www.secdev.org')\n"
     ]
    }
   ],
   "source": [
    "print(p.dst)  # first layer that has an src field, here Ether\n",
    "print(p[IP].src)  # explicitly access the src field of the IP layer\n",
    "\n",
    "# sprintf() is a useful method to display fields\n",
    "print(p.sprintf(\"%Ether.src% > %Ether.dst%\\n%IP.src% > %IP.dst%\"))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Scapy uses default values that work most of the time. For example, `TCP()` is a SYN segment to port 80."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 9,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "S http\n"
     ]
    }
   ],
   "source": [
    "print(p.sprintf(\"%TCP.flags% %TCP.dport%\"))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Moreover, Scapy has implicit packets. For example, they are useful to make the TTL field value vary from 1 to 5 to mimic traceroute."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 11,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "text/plain": [
       "[<IP  frag=0 ttl=1 proto=icmp |<ICMP  |>>,\n",
       " <IP  frag=0 ttl=2 proto=icmp |<ICMP  |>>,\n",
       " <IP  frag=0 ttl=3 proto=icmp |<ICMP  |>>,\n",
       " <IP  frag=0 ttl=4 proto=icmp |<ICMP  |>>,\n",
       " <IP  frag=0 ttl=5 proto=icmp |<ICMP  |>>]"
      ]
     },
     "execution_count": 11,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "[p for p in IP(ttl=(1,5))/ICMP()]"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Sending and receiving"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Currently, you know how to build packets with Scapy. The next step is to send them over the network !\n",
    "\n",
    "The `sr1()` function sends a packet and returns the corresponding answer. `srp1()` does the same for layer two packets, i.e. Ethernet. If you are only interested in sending packets `send()` is your friend.\n",
    "\n",
    "As an example, we can use the DNS protocol to get www.example.com IPv4 address."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 23,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "\n",
      "Received 19 packets, got 1 answers, remaining 0 packets\n",
      "Begin emission:\n",
      "Finished to send 1 packets.\n"
     ]
    },
    {
     "data": {
      "text/plain": [
       "<DNSRR  rrname='www.example.com.' type=A rclass=IN ttl=10011 rdata='93.184.216.34' |>"
      ]
     },
     "execution_count": 23,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "p = sr1(IP(dst=\"8.8.8.8\")/UDP()/DNS(qd=DNSQR()))\n",
    "p[DNS].an"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Another alternative is the `sr()` function. Like `srp1()`, the `sr1()` function can be used for layer 2 packets."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 47,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "\n",
      "Received 7 packets, got 6 answers, remaining 0 packets\n",
      "Begin emission:\n",
      "Finished to send 6 packets.\n"
     ]
    },
    {
     "data": {
      "text/plain": [
       "(<Results: TCP:0 UDP:0 ICMP:6 Other:0>,\n",
       " <Unanswered: TCP:0 UDP:0 ICMP:0 Other:0>)"
      ]
     },
     "execution_count": 47,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "r, u = srp(Ether()/IP(dst=\"8.8.8.8\", ttl=(5,10))/UDP()/DNS(rd=1, qd=DNSQR(qname=\"www.example.com\")))\n",
    "r, u"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "`sr()` sent a list of packets, and returns two variables, here `r` and `u`, where:\n",
    "1. `r` is a list of results (i.e tuples of the packet sent and its answer)\n",
    "2. `u` is a list of unanswered packets"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 48,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Ether / IP / UDP / DNS Qry \"www.example.com\" \n",
      "Ether / IP / ICMP / IPerror / UDPerror / DNS Qry \"www.example.com.\" \n"
     ]
    },
    {
     "data": {
      "text/plain": [
       "<ICMP  type=time-exceeded code=ttl-zero-during-transit chksum=0x50d6 reserved=0 length=0 unused=None |<IPerror  version=4L ihl=5L tos=0x0 len=61 id=1 flags= frag=0L ttl=1 proto=udp chksum=0xf389 src=172.20.10.2 dst=8.8.8.8 options=[] |<UDPerror  sport=domain dport=domain len=41 chksum=0x593a |<DNS  id=0 qr=0L opcode=QUERY aa=0L tc=0L rd=1L ra=0L z=0L ad=0L cd=0L rcode=ok qdcount=1 ancount=0 nscount=0 arcount=0 qd=<DNSQR  qname='www.example.com.' qtype=A qclass=IN |> an=None ns=None ar=None |>>>>"
      ]
     },
     "execution_count": 48,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "# Access the first tuple\n",
    "print(r[0][0].summary())  # the packet sent\n",
    "print(r[0][1].summary())  # the answer received\n",
    "\n",
    "# Access the ICMP layer. Scapy received a time-exceeded error message\n",
    "r[0][1][ICMP]"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "With Scapy, list of packets, such as `r` or `u`, can be easily written to, or read from PCAP files."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 50,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<Ether  dst=f4:ce:46:a9:e0:4b src=34:95:db:04:3c:29 type=IPv4 |<IP version=4L ihl=5L tos=0x0 len=61 id=1 flags= frag=0L ttl=5 proto=udp chksum=0xb6e3 src=192.168.46.20 dst=8.8.8.8 options=[] |<UDP sport=domain dport=domain len=41 chksum=0xb609 |<DNS  id=0 qr=0L opcode=QUERY aa=0L tc=0L rd=1L ra=0L z=0L ad=0L cd=0L rcode=ok qdcount=1 ancount=0 nscount=0 arcount=0 qd=<DNSQR  qname='www.example.com.' qtype=A qclass=IN |> an=None ns=None ar=None |>>>>"
      ]
     },
     "execution_count": 50,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "wrpcap(\"scapy.pcap\", r)\n",
    "\n",
    "pcap_p = rdpcap(\"scapy.pcap\")\n",
    "pcap_p[0]"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Sniffing the network is as straightforward as sending and receiving packets. The `sniff()` function returns a list of Scapy packets, that can be manipulated as previously described."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 52,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<Sniffed: TCP:0 UDP:2 ICMP:0 Other:0>"
      ]
     },
     "execution_count": 52,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "s = sniff(count=2)\n",
    "s"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "`sniff()` has many arguments. The `prn` one accepts a function name that will be called on received packets. Using the `lambda` keyword, Scapy could be used to mimic the `tshark` command behavior."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 53,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Ether / IP / TCP 172.20.10.2:52664 > 216.58.208.200:https A\n",
      "Ether / IP / TCP 216.58.208.200:https > 172.20.10.2:52664 A\n"
     ]
    },
    {
     "data": {
      "text/plain": [
       "<Sniffed: TCP:2 UDP:0 ICMP:0 Other:0>"
      ]
     },
     "execution_count": 53,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "sniff(count=2, prn=lambda p: p.summary())"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Alternatively, Scapy can use OS sockets to send and receive packets. The following example assigns an UDP socket to a Scapy `StreamSocket`, which is then used to query www.example.com IPv4 address.\n",
    "Unlike other Scapy sockets, `StreamSockets` do not require root privileges."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 79,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "\n",
      "Received 1 packets, got 1 answers, remaining 0 packets\n",
      "Begin emission:\n",
      "Finished to send 1 packets.\n"
     ]
    },
    {
     "data": {
      "text/plain": [
       "<DNS  id=0 qr=1L opcode=QUERY aa=0L tc=0L rd=1L ra=1L z=0L ad=0L cd=0L rcode=ok qdcount=1 ancount=1 nscount=0 arcount=0 qd=<DNSQR  qname='www.example.com.' qtype=A qclass=IN |> an=<DNSRR  rrname='www.example.com.' type=A rclass=IN ttl=19681 rdata='93.184.216.34' |> ns=None ar=None |>"
      ]
     },
     "execution_count": 79,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "import socket\n",
    "\n",
    "sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # create an UDP socket\n",
    "sck.connect((\"8.8.8.8\", 53))  # connect to 8.8.8.8 on 53/UDP\n",
    "\n",
    "# Create the StreamSocket and gives the class used to decode the answer\n",
    "ssck = StreamSocket(sck)\n",
    "ssck.basecls = DNS\n",
    "\n",
    "# Send the DNS query\n",
    "ssck.sr1(DNS(rd=1, qd=DNSQR(qname=\"www.example.com\")))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Visualization\n",
    "Parts of the following examples require the [matplotlib](http://matplotlib.org/) module."
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "With `srloop()`, we can send 100 ICMP packets to 8.8.8.8 and 8.8.4.4."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 25,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": []
    }
   ],
   "source": [
    "ans, unans = srloop(IP(dst=[\"8.8.8.8\", \"8.8.4.4\"])/ICMP(), inter=.1, timeout=.1, count=100, verbose=False)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Then we can use the results to plot the IP id values."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 26,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "image/png": "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\n3vwBiKfkY/e6SeUAAAAASUVORK5CYII=\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0x7f2c23bfbc50>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    },
    {
     "data": {
      "text/plain": [
       "[[<matplotlib.lines.Line2D at 0x7f2c2e113d10>],\n",
       " [<matplotlib.lines.Line2D at 0x7f2c2e113f10>]]"
      ]
     },
     "execution_count": 26,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "%matplotlib inline\n",
    "ans.multiplot(lambda x, y: (y[IP].src, (y.time, y[IP].id)), plot_xy=True)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "The `raw()` constructor can be used to \"build\" the packet's bytes as they would be sent on the wire."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 8,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "b'E\\x00\\x00=\\x00\\x01\\x00\\x00@\\x11|\\xad\\x7f\\x00\\x00\\x01\\x7f\\x00\\x00\\x01\\x005\\x005\\x00)\\xb6\\xd3\\x00\\x00\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x03www\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01'\n"
     ]
    }
   ],
   "source": [
    "pkt = IP() / UDP() / DNS(qd=DNSQR())\n",
    "print(repr(raw(pkt)))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Since some people cannot read this representation, Scapy can:\n",
    "  - give a summary for a packet"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 10,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "IP / UDP / DNS Qry \"www.example.com\" \n"
     ]
    }
   ],
   "source": [
    "print(pkt.summary())"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "  - \"hexdump\" the packet's bytes"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 18,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "0000   45 00 00 3D 00 01 00 00  40 11 7C AD 7F 00 00 01   E..=....@.|.....\n",
      "0010   7F 00 00 01 00 35 00 35  00 29 B6 D3 00 00 01 00   .....5.5.)......\n",
      "0020   00 01 00 00 00 00 00 00  03 77 77 77 07 65 78 61   .........www.exa\n",
      "0030   6D 70 6C 65 03 63 6F 6D  00 00 01 00 01            mple.com.....\n"
     ]
    }
   ],
   "source": [
    "hexdump(pkt)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "  - dump the packet, layer by layer, with the values for each field"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 11,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "###[ IP ]###\n",
      "  version   = 4\n",
      "  ihl       = None\n",
      "  tos       = 0x0\n",
      "  len       = None\n",
      "  id        = 1\n",
      "  flags     = \n",
      "  frag      = 0\n",
      "  ttl       = 64\n",
      "  proto     = udp\n",
      "  chksum    = None\n",
      "  src       = 127.0.0.1\n",
      "  dst       = 127.0.0.1\n",
      "  \\options   \\\n",
      "###[ UDP ]###\n",
      "     sport     = domain\n",
      "     dport     = domain\n",
      "     len       = None\n",
      "     chksum    = None\n",
      "###[ DNS ]###\n",
      "        id        = 0\n",
      "        qr        = 0\n",
      "        opcode    = QUERY\n",
      "        aa        = 0\n",
      "        tc        = 0\n",
      "        rd        = 1\n",
      "        ra        = 0\n",
      "        z         = 0\n",
      "        ad        = 0\n",
      "        cd        = 0\n",
      "        rcode     = ok\n",
      "        qdcount   = 1\n",
      "        ancount   = 0\n",
      "        nscount   = 0\n",
      "        arcount   = 0\n",
      "        \\qd        \\\n",
      "         |###[ DNS Question Record ]###\n",
      "         |  qname     = 'www.example.com'\n",
      "         |  qtype     = A\n",
      "         |  qclass    = IN\n",
      "        an        = None\n",
      "        ns        = None\n",
      "        ar        = None\n"
     ]
    }
   ],
   "source": [
    "pkt.show()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "  - render a pretty and handy dissection of the packet"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 15,
   "metadata": {
    "scrolled": true
   },
   "outputs": [
    {
     "data": {
      "image/png": "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\n",
      "text/plain": [
       "<pyx.canvas.canvas instance at 0x7f2c2e228bd8>"
      ]
     },
     "execution_count": 15,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "pkt.canvas_dump()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Scapy has a `traceroute()` function, which basically runs a `sr(IP(ttl=(1..30))` and creates a `TracerouteResult` object, which is a specific subclass of `SndRcvList()`."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 22,
   "metadata": {
    "scrolled": true
   },
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Begin emission:\n",
      "Finished to send 15 packets.\n",
      "\n",
      "Received 17 packets, got 15 answers, remaining 0 packets\n",
      "   217.25.178.5:tcp80 \n",
      "1  192.168.46.254  11 \n",
      "2  172.28.0.1      11 \n",
      "3  80.10.115.251   11 \n",
      "4  10.123.205.82   11 \n",
      "5  193.252.98.161  11 \n",
      "6  193.252.137.74  11 \n",
      "7  193.251.132.183 11 \n",
      "8  130.117.49.41   11 \n",
      "9  154.25.7.150    11 \n",
      "10 154.25.7.150    11 \n",
      "11 149.6.166.166   11 \n",
      "12 149.6.166.166   11 \n",
      "13 217.25.178.5    SA \n",
      "14 217.25.178.5    SA \n",
      "15 217.25.178.5    SA \n"
     ]
    }
   ],
   "source": [
    "ans, unans = traceroute('www.secdev.org', maxttl=15)"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "The result can be plotted with `.world_trace()` (this requires GeoIP module and data, from [MaxMind](https://www.maxmind.com/))"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 23,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "image/png": "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\n",
      "text/plain": [
       "<matplotlib.figure.Figure at 0x7f2c2c0b2fd0>"
      ]
     },
     "metadata": {},
     "output_type": "display_data"
    },
    {
     "data": {
      "text/plain": [
       "[[<matplotlib.lines.Line2D at 0x7f2c23b62850>]]"
      ]
     },
     "execution_count": 23,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "ans.world_trace()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "The `PacketList.make_table()` function can be very helpful. Here is a simple \"port scanner\":"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 29,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "          45.33.32.156 45.33.49.119 \n",
      "tcp/22    SA           SA           \n",
      "tcp/31337 SA           RA           \n",
      "tcp/443   RA           SA           \n",
      "tcp/80    SA           SA           \n",
      "udp/53    dest-unreach -            \n"
     ]
    }
   ],
   "source": [
    "ans = sr(IP(dst=[\"scanme.nmap.org\", \"nmap.org\"])/TCP(dport=[22, 80, 443, 31337]), timeout=3, verbose=False)[0]\n",
    "ans.extend(sr(IP(dst=[\"scanme.nmap.org\", \"nmap.org\"])/UDP(dport=53)/DNS(qd=DNSQR()), timeout=3, verbose=False)[0])\n",
    "ans.make_table(lambda x, y: (x[IP].dst, x.sprintf('%IP.proto%/{TCP:%r,TCP.dport%}{UDP:%r,UDP.dport%}'), y.sprintf('{TCP:%TCP.flags%}{ICMP:%ICMP.type%}')))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Implementing a new protocol"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Scapy can be easily extended to support new protocols.\n",
    "\n",
    "The following example defines DNS over TCP. The `DNSTCP` class inherits from `Packet` and defines two field: the length, and the real DNS message. The `length_of` and `length_from` arguments link the `len` and `dns` fields together. Scapy will be able to automatically compute the `len` value."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 119,
   "metadata": {},
   "outputs": [],
   "source": [
    "class DNSTCP(Packet):\n",
    "    name = \"DNS over TCP\"\n",
    "    \n",
    "    fields_desc = [ FieldLenField(\"len\", None, fmt=\"!H\", length_of=\"dns\"),\n",
    "                    PacketLenField(\"dns\", 0, DNS, length_from=lambda p: p.len)]\n",
    "    \n",
    "    # This method tells Scapy that the next packet must be decoded with DNSTCP\n",
    "    def guess_payload_class(self, payload):\n",
    "        return DNSTCP"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "This new packet definition can be direcly used to build a DNS message over TCP."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 120,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "text/plain": [
       "<DNSTCP  len=12 dns=<DNS  id=0 qr=0L opcode=QUERY aa=0L tc=0L rd=0L ra=0L z=0L ad=0L cd=0L rcode=ok qdcount=0 ancount=0 nscount=0 arcount=0 |> |>"
      ]
     },
     "execution_count": 120,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "# Build then decode a DNS message over TCP\n",
    "DNSTCP(raw(DNSTCP(dns=DNS())))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Modifying the previous `StreamSocket` example to use TCP allows to use the new `DNSCTP` layer easily."
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 122,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "\n",
      "Received 1 packets, got 1 answers, remaining 0 packets\n",
      "Begin emission:\n",
      "Finished to send 1 packets.\n"
     ]
    },
    {
     "data": {
      "text/plain": [
       "<DNSTCP  len=49 dns=<DNS  id=0 qr=1L opcode=QUERY aa=0L tc=0L rd=1L ra=1L z=0L ad=0L cd=0L rcode=ok qdcount=1 ancount=1 nscount=0 arcount=0 qd=<DNSQR  qname='www.example.com.' qtype=A qclass=IN |> an=<DNSRR  rrname='www.example.com.' type=A rclass=IN ttl=12101 rdata='93.184.216.34' |> ns=None ar=None |> |>"
      ]
     },
     "execution_count": 122,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "import socket\n",
    "\n",
    "sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create an TCP socket\n",
    "sck.connect((\"8.8.8.8\", 53))  # connect to 8.8.8.8 on 53/TCP\n",
    "\n",
    "# Create the StreamSocket and gives the class used to decode the answer\n",
    "ssck = StreamSocket(sck)\n",
    "ssck.basecls = DNSTCP\n",
    "\n",
    "# Send the DNS query\n",
    "ssck.sr1(DNSTCP(dns=DNS(rd=1, qd=DNSQR(qname=\"www.example.com\"))))"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Scapy as a module"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "So far, Scapy was only used from the command line. It is also a Python module than can be used to build specific network tools, such as ping6.py:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "    from scapy.all import *\n",
    "    import argparse\n",
    "\n",
    "    parser = argparse.ArgumentParser(description=\"A simple ping6\")\n",
    "    parser.add_argument(\"ipv6_address\", help=\"An IPv6 address\")\n",
    "    args = parser.parse_args()\n",
    "\n",
    "    print(sr1(IPv6(dst=args.ipv6_address)/ICMPv6EchoRequest(), verbose=0).summary())"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Answering machines"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "A lot of attack scenarios look the same: you want to wait for a specific packet, then send an answer to trigger the attack.\n",
    "\n",
    "To this extent, Scapy provides the `AnsweringMachine` object. Two methods are especially useful:\n",
    "1. `is_request()`: return True if the `pkt` is the expected request\n",
    "2. `make_reply()`: return the packet that must be sent\n",
    "\n",
    "The following example uses Scapy Wi-Fi capabilities to pretend that a \"Scapy !\" access point exists.\n",
    "\n",
    "Note: your Wi-Fi interface must be set to monitor mode !"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 129,
   "metadata": {},
   "outputs": [],
   "source": [
    "# Specify the Wi-Fi monitor interface\n",
    "#conf.iface = \"mon0\"  # uncomment to test\n",
    "\n",
    "# Create an answering machine\n",
    "class ProbeRequest_am(AnsweringMachine):\n",
    "  function_name = \"pram\"\n",
    "\n",
    "  # The fake mac of the fake access point\n",
    "  mac = \"00:11:22:33:44:55\"\n",
    "\n",
    "  def is_request(self, pkt):\n",
    "    return Dot11ProbeReq in pkt\n",
    "\n",
    "  def make_reply(self, req):\n",
    "\n",
    "    rep = RadioTap()\n",
    "    # Note: depending on your Wi-Fi card, you might need a different header than RadioTap()\n",
    "    rep /= Dot11(addr1=req.addr2, addr2=self.mac, addr3=self.mac, ID=RandShort(), SC=RandShort())\n",
    "    rep /= Dot11ProbeResp(cap=\"ESS\", timestamp=time.time())\n",
    "    rep /= Dot11Elt(ID=\"SSID\",info=\"Scapy !\")\n",
    "    rep /= Dot11Elt(ID=\"Rates\",info=b'\\x82\\x84\\x0b\\x16\\x96')\n",
    "    rep /= Dot11Elt(ID=\"DSset\",info=chr(10))\n",
    "\n",
    "    OK,return rep\n",
    "\n",
    "# Start the answering machine\n",
    "#ProbeRequest_am()()  # uncomment to test"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "## Cheap Man-in-the-middle with NFQUEUE"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "NFQUEUE is an iptables target than can be used to transfer packets to userland process. As a nfqueue module is available in Python, you can take advantage of this Linux feature to perform Scapy based MiTM.\n",
    "\n",
    "This example intercepts ICMP Echo request messages sent to 8.8.8.8, sent with the ping command, and modify their sequence numbers. In order to pass packets to Scapy, the following `iptable` command put packets into the NFQUEUE #2807:\n",
    "\n",
    "$ sudo iptables -I OUTPUT --destination 8.8.8.8 -p icmp -o eth0 -j NFQUEUE --queue-num 2807"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "    from scapy.all import *\n",
    "    import nfqueue, socket\n",
    "\n",
    "    def scapy_cb(i, payload):\n",
    "      s = payload.get_data()  # get and parse the packet\n",
    "      p = IP(s)\n",
    "\n",
    "      # Check if the packet is an ICMP Echo Request to 8.8.8.8\n",
    "      if p.dst == \"8.8.8.8\" and ICMP in p:\n",
    "        # Delete checksums to force Scapy to compute them\n",
    "        del(p[IP].chksum, p[ICMP].chksum)\n",
    "        \n",
    "        # Set the ICMP sequence number to 0\n",
    "        p[ICMP].seq = 0\n",
    "        \n",
    "        # Let the modified packet go through\n",
    "        ret = payload.set_verdict_modified(nfqueue.NF_ACCEPT, raw(p), len(p))\n",
    "        \n",
    "      else:\n",
    "        # Accept all packets\n",
    "        payload.set_verdict(nfqueue.NF_ACCEPT)\n",
    "\n",
    "    # Get an NFQUEUE handler\n",
    "    q = nfqueue.queue()\n",
    "    # Set the function that will be call on each received packet\n",
    "    q.set_callback(scapy_cb)\n",
    "    # Open the queue & start parsing packes\n",
    "    q.fast_open(2807, socket.AF_INET)\n",
    "    q.try_run()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# Automaton"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "When more logic is needed, Scapy provides a clever way abstraction to define an automaton. In a nutshell, you need to define an object that inherits from `Automaton`, and implement specific methods:\n",
    "- states: using the `@ATMT.state` decorator. They usually do nothing\n",
    "- conditions: using the `@ATMT.condition` and `@ATMT.receive_condition` decorators. They describe how to go from one state to another\n",
    "- actions: using the `ATMT.action` decorator. They describe what to do, like sending a back, when changing state"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "The following example does nothing more than trying to mimic a TCP scanner:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 6,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "-> SYN\n",
      "<- SYN/ACK\n"
     ]
    }
   ],
   "source": [
    "class TCPScanner(Automaton):\n",
    "\n",
    "    @ATMT.state(initial=1)\n",
    "    def BEGIN(self):\n",
    "        pass\n",
    "\n",
    "    @ATMT.state()\n",
    "    def SYN(self):\n",
    "        print(\"-> SYN\")\n",
    "\n",
    "    @ATMT.state()\n",
    "    def SYN_ACK(self):\n",
    "        print(\"<- SYN/ACK\")\n",
    "        raise self.END()\n",
    "\n",
    "    @ATMT.state()\n",
    "    def RST(self):\n",
    "        print(\"<- RST\")\n",
    "        raise self.END()\n",
    "\n",
    "    @ATMT.state()\n",
    "    def ERROR(self):\n",
    "        print(\"!! ERROR\")\n",
    "        raise self.END()\n",
    "    @ATMT.state(final=1)\n",
    "    def END(self):\n",
    "        pass\n",
    "    \n",
    "    @ATMT.condition(BEGIN)\n",
    "    def condition_BEGIN(self):\n",
    "        raise self.SYN()\n",
    "\n",
    "    @ATMT.condition(SYN)\n",
    "    def condition_SYN(self):\n",
    "\n",
    "        if random.randint(0, 1):\n",
    "            raise self.SYN_ACK()\n",
    "        else:\n",
    "            raise self.RST()\n",
    "\n",
    "    @ATMT.timeout(SYN, 1)\n",
    "    def timeout_SYN(self):\n",
    "        raise self.ERROR()\n",
    "\n",
    "TCPScanner().run()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 7,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "-> SYN\n",
      "<- RST\n"
     ]
    }
   ],
   "source": [
    "TCPScanner().run()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# Pipes"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Pipes are an advanced Scapy feature that aims sniffing, modifying and printing packets. The API provides several buildings blocks. All of them, have high entries and exits (>>) as well as low (>) ones.\n",
    "\n",
    "For example, the `CliFeeder` is used to send message from the Python command line to a low exit. It can be combined to the `InjectSink` that reads message on its low entry and inject them to the specified network interface. These blocks can be combined as follows:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "# Instantiate the blocks\n",
    "clf = CLIFeeder()\n",
    "ijs = InjectSink(\"enx3495db043a28\")\n",
    "\n",
    "# Plug blocks together\n",
    "clf > ijs\n",
    "\n",
    "# Create and start the engine\n",
    "pe = PipeEngine(clf)\n",
    "pe.start()"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "Packet can be sent using the following command on the prompt:"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": [
    "clf.send(\"Hello Scapy !\")"
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 2",
   "language": "python",
   "name": "python2"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 2
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython2",
   "version": "2.7.12"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 1
}
