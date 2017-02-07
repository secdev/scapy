## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Arnaud Ebalard, Maxence Tury
## This program is published under a GPLv2 license

"""
Tools for handling TLS sessions and digital certificates.
"""

from scapy.config import conf

if not conf.crypto_valid:
    import logging
    log_loading = logging.getLogger("scapy.loading")
    log_loading.info("Can't import python-cryptography v1.7+. Disabled PKCS #1 signing/verifying.")

try:
    import ecdsa
except ImportError:
    import logging
    log_loading = logging.getLogger("scapy.loading")
    log_loading.info("Can't import python ecdsa lib. Disabled certificate manipulation tools")
else:
    from scapy.layers.tls.cert import *
