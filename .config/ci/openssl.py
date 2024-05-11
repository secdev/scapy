# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Create a duplicate of the OpenSSL config to be able to use TLS < 1.2
This returns the path to this new config file.
"""

import os
import re
import subprocess
import tempfile

# Get OpenSSL config file
OPENSSL_DIR = re.search(
    b"OPENSSLDIR: \"(.*)\"",
    subprocess.Popen(
        ["openssl", "version", "-d"],
        stdout=subprocess.PIPE
    ).communicate()[0]
).group(1).decode()
OPENSSL_CONFIG = os.path.join(OPENSSL_DIR, 'openssl.cnf')

# https://www.openssl.org/docs/manmaster/man5/config.html
DATA = b"""
openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_configuration

[ssl_configuration]
system_default = tls_system_default

[tls_system_default]
MinProtocol = TLSv1
CipherString = DEFAULT:@SECLEVEL=0
Options = UnsafeLegacyRenegotiation
""".strip()

# Copy and edit
with tempfile.NamedTemporaryFile(suffix=".cnf", delete=False) as fd:
    fd.write(DATA)
    print(fd.name)
