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
sudo sed -i '/^SLAPD_SERVICES/ c\SLAPD_SERVICES="ldap:/// ldapi:/// ldaps://"' /etc/default/slapd
sudo service slapd restart

# Copy config template and replace variables.
CUR=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
openldap_conf=$(mktemp /tmp/scapy_openldapconf_XXXXXX.ldif)
pkipath=$(realpath "$CUR/../../../test/scapy/layers/tls/pki")
cp $CUR/config.ldif $openldap_conf
sed -i "s@{{CAFILE}}@${pkipath}/ca_cert.pem@g" $openldap_conf
sed -i "s@{{CRTFILE}}@${pkipath}/srv_cert.pem@g" $openldap_conf
sed -i "s@{{KEYFILE}}@${pkipath}/srv_key.pem@g" $openldap_conf
echo "Temporary config stored in $openldap_conf"

sudo ldapmodify -Y EXTERNAL -H "ldapi:///" -w Bonjour1 -f $openldap_conf -c
sudo ldapadd    -D "cn=admin,dc=scapy,dc=net" -w Bonjour1 -H "ldapi:///" -f $CUR/testdata.ldif -c
