***********************
Calling Scapy functions
***********************

This section provides some examples that show how to benefit from Scapy
functions in your own code.

UDP checksum
============

The following example explains how to use the checksum() function to compute and
UDP checksum manually. The following steps must be performed:

1. compute the UDP pseudo header as described in RFC768
2. build a UDP packet with Scapy with p[UDP].chksum=0
3. call checksum() with the pseudo header and the UDP packet

::

  from scapy.all import *

  # Get the UDP checksum computed by Scapy
  packet = IP(dst="10.11.12.13", src="10.11.12.14")/UDP()/DNS()
  packet = IP(raw(packet))  # Build packet (automatically done when sending)
  checksum_scapy = packet[UDP].chksum

  # Set the UDP checksum to 0 and compute the checksum 'manually'
  packet = IP(dst="10.11.12.13", src="10.11.12.14")/UDP(chksum=0)/DNS()
  packet_raw = raw(packet)
  udp_raw = packet_raw[20:]
  # in4_chksum is used to automatically build a pseudo-header
  chksum = in4_chksum(socket.IPPROTO_UDP, packet[IP], udp_raw)  # For more infos, call "help(in4_chksum)"

  assert(checksum_scapy == chksum)
