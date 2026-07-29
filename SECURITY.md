# Security Policy

We take security seriously. If you find a critical bug report, please reach out privately using [Github's security tab](https://github.com/secdev/scapy/security).
Please note however that we only provide support for the **latest** version of Scapy (master).

### Examples of what counts as a vulnerability in Scapy

* a DoS during parsing: provide a packet that triggers an infinite loop when parsing (high issue), or takes a quadratic amount of resources (low issue)
* a packet that stop the dissection process entirely (`sniff` / `PcapReader` / `rdpcap`)
* a packet that triggers an arbitrary code execution (RCE), unrestricted read of files, or any similar high Confidentiality/Integrity bugs

### Examples of what doesn't count as a vulnerability in Scapy

* a packet that crashes a dissector and fallbacks to being parsed as `Raw`: we have a [conservative approach](https://github.com/secdev/scapy/blob/caa005dae9bddeb93b11286327149c824db7732a/scapy/supersocket.py#L218-L227) with dissector failures
  where a crash doesn't stop the parsing thread. This is not a security issue, but is still a bug so please open a public issue !
* a DoS that is triggered by dissecting a packet that is too large to exist on the wire (e.g. packet larger than the MTU)
* a DoS that is triggered when crafting a packet (and that is not a response to a stimulus, e.g. answering machines, automatons, etc.)
* having `conf.debug_dissector != 0`
* anything that requires changing Scapy's configuration or caching files, including but not limited to `.config/scapy/*`, `.cache/scapy/*`
