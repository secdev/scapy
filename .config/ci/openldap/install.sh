#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# Install an OpenLDAP test server

# Pre-populate some setup questions
sudo debconf-set-selections <<< 'slapd slapd/password2 password Bonjour1'
sudo debconf-set-selections <<< 'slapd slapd/password1 password Bonjour1'
sudo debconf-set-selections <<< 'slapd slapd/domain string scapy.net'

# Run setup
sudo apt-get -qy install slapd

# Enable LDAPs
echo "Enabling HTTPS on slapd..."
sudo sed -i '/^SLAPD_SERVICES/ c\SLAPD_SERVICES="ldap:/// ldapi:/// ldaps://"' /etc/default/slapd
sudo systemctl restart slapd

# Calculate the paths we're going to need.
CUR=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
PKIPATH=$(realpath "$CUR/../../../test/scapy/layers/tls/pki")
OLDAPPATH=$(mktemp -d -t scapy_openldap_XXXX)

# Copy certificates to temp path
cp ${PKIPATH}/ca_cert.pem ${OLDAPPATH}
cp ${PKIPATH}/srv_cert.pem ${OLDAPPATH}
cp ${PKIPATH}/srv_key.pem ${OLDAPPATH}
chmod a+rx -R ${OLDAPPATH}

# Copy config template and replace variables.
echo "Creating OpenLDAP config..."
openldap_conf=${OLDAPPATH}/openldap_config.ldif
cp $CUR/config.ldif $openldap_conf
sed -i "s@{{CAFILE}}@${OLDAPPATH}/ca_cert.pem@g" $openldap_conf
sed -i "s@{{CRTFILE}}@${OLDAPPATH}/srv_cert.pem@g" $openldap_conf
sed -i "s@{{KEYFILE}}@${OLDAPPATH}/srv_key.pem@g" $openldap_conf

echo "Applying OpenLDAP config..."
sudo ldapmodify -Y EXTERNAL -H "ldapi:///" -w Bonjour1 -f $openldap_conf -c
echo "Adding initial dummy data..."
sudo ldapadd    -D "cn=admin,dc=scapy,dc=net" -w Bonjour1 -H "ldapi:///" -f $CUR/testdata.ldif -c
