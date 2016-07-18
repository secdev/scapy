## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Arnaud Ebalard, Maxence Tury
## This program is published under a GPLv2 license

"""
Tools for handling TLS sessions and digital certificates.
"""

try:
    import Crypto
except ImportError:
    import logging
    log_loading = logging.getLogger("scapy.loading")
    log_loading.info("Can't import python Crypto lib. Disabled certificate manipulation tools")

try:
    import ecdsa
except ImportError:
    import logging
    log_loading = logging.getLogger("scapy.loading")
    log_loading.info("Can't import python ecdsa lib. Disabled certificate manipulation tools")
else:
    from scapy.layers.tls.cert import *
