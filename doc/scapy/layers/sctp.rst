****
SCTP
****

SCTP is a relatively young transport-layer protocol combining both TCP and UDP characteristics. The `RFC 3286 <https://tools.ietf.org/html/rfc3286>`_ introduces it and its description lays in the `RFC 4960 <https://tools.ietf.org/html/rfc4960>`_.

It is not broadly used, its mainly present in core networks operated by telecommunication companies, to support VoIP for instance.


Enabling dynamic addressing reconfiguration and chunk authentication capabilities
---------------------------------------------------------------------------------

If you are trying to discuss with SCTP servers, you may be interested in capabilities added in `RFC 4895 <https://tools.ietf.org/html/rfc4895>`_ which describe how to authenticated some SCTP chunks, and/or `RFC 5061 <https://tools.ietf.org/html/rfc5061>`_ to dynamically reconfigure the IP address of a SCTP association.

These capabilities are not always enabled by default on Linux. Scapy does not need any modification on its end, but SCTP servers may need specific activation.

To enable the RFC 4895 about authenticating chunks::

    $ sudo echo 1 > /proc/sys/net/sctp/auth_enable

To enable the RFC 5061 about dynamic address reconfiguration::

    $ sudo echo 1 > /proc/sys/net/sctp/addip_enable

You may also want to use the dynamic address reconfiguration without necessarily enabling the chunk authentication::

    $ sudo echo 1 > /proc/sys/net/sctp/addip_noauth_enable