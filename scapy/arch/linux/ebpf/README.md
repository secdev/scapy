# eBPF Experimental Support

This directory contains the Scapy eBPF playground that aims to get process information for each sent and received packets. This is still under developpment, and needs testing.

## Testing


A simple demo will sniff 10 IPv4 packets (excluding SSH), and display their summaries along with process information:
```shell
python3 -m scapy.arch.linux.ebpf
Scapy + eBPF = <3

1115177 b'curl' Ether / IP / TCP 10.211.55.4:51194 > 104.21.5.178:https S
1115177 b'curl' Ether / IP / TCP 104.21.5.178:https > 10.211.55.4:51194 SA
1115177 b'curl' Ether / IP / TCP 10.211.55.4:51194 > 104.21.5.178:https A
1115177 b'curl' Ether / IP / TCP 10.211.55.4:51194 > 104.21.5.178:https PA / Raw
1115177 b'curl' Ether / IP / TCP 104.21.5.178:https > 10.211.55.4:51194 A
1115177 b'curl' Ether / IP / TCP 104.21.5.178:https > 10.211.55.4:51194 PA / Raw
1115177 b'curl' Ether / IP / TCP 104.21.5.178:https > 10.211.55.4:51194 PA / Raw
1115177 b'curl' Ether / IP / TCP 10.211.55.4:51194 > 104.21.5.178:https A
1115177 b'curl' Ether / IP / TCP 10.211.55.4:51194 > 104.21.5.178:https A
1115177 b'curl' Ether / IP / TCP 104.21.5.178:https > 10.211.55.4:51194 PA / Raw
```

An interactive mode is also available tp experiment with potential extended usages:
```shell
# python3 -m scapy.arch.linux.ebpf -i -H
Welcome to Scapy (2.6.0rc1.dev28)
Scapy + eBPF = <3
>>> l = sniff(process_information=True)
```

## TODO

* [ ] Improve Program_security_sk_classify_flow
  * [ ] ICMPv4 support
  * [ ] IPv6 & ICMPv6 support