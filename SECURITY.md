# Security Policy

We take security seriously. If you find a critical bug report, please reach out privately using [Github's security tab](https://github.com/secdev/scapy/security).
Please note however that we only provide support for the **latest** version of Scapy (master).

Please include a minimal working example against an unmodified checkout, plus a negative control where the same exchange works without the triggering packet.

### Examples of what counts as a vulnerability in Scapy

* a DoS during parsing: provide a packet that triggers an infinite loop when parsing (high issue), or takes a quadratic amount of resources (low issue)
* a packet that stop the dissection process entirely (`sniff` / `PcapReader` / `rdpcap`)
* a packet that triggers an arbitrary code execution (RCE), unrestricted read of files, or any similar high Confidentiality/Integrity bugs
* an issue in the implementation of one of the `AnsweringMachine` or `Automaton` that qualifies as a high/critical security issue (e.g. in `SMB_Client`, `TLSClientAutomaton`, `DNS_am`, etc.). For instance: bad checking of a signature, out-of-spec replays, a DoS, etc.

### Examples of what doesn't count as a vulnerability in Scapy

* a packet that crashes a dissector and fallbacks to being parsed as `Raw`: we have a [conservative approach](https://github.com/secdev/scapy/blob/caa005dae9bddeb93b11286327149c824db7732a/scapy/supersocket.py#L218-L227) with dissector failures
  where a crash doesn't stop the parsing thread. This is not a security issue, but is still a bug so please open a public issue !
* a DoS that is triggered by dissecting a packet that is too large to exist on the wire (e.g. packet larger than the MTU)
* a DoS that is triggered when crafting a packet, unless the packet is crafted in response to a stimulus (e.g. answering machines, automatons, etc.)
* having `conf.debug_dissector != 0`
* anything that requires changing Scapy's configuration or files on disk, including but not limited to `.config/scapy/*`, `.cache/scapy/*`
* a protocol that allows out-of-spec packets to be parsed or built: this is expected in Scapy, and isn't even considered a bug.

### Out of scope

* `scapy/modules/krack/*`: this code is obsolete.
