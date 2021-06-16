# This file is part of Scapy
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

# https://askubuntu.com/a/1233456
HEADER = b"openssl_conf = default_conf\n"
FOOTER = b"""
[ default_conf ]

ssl_conf = ssl_sect

[ssl_sect]

system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT:@SECLEVEL=1
"""

# Copy and edit
with open(OPENSSL_CONFIG, 'rb') as fd:
    DATA = fd.read()

DATA = HEADER + DATA + FOOTER

with tempfile.NamedTemporaryFile(suffix=".cnf", delete=False) as fd:
    fd.write(DATA)
    print(fd.name)
