## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
X.509 certificates.
"""

from scapy.asn1packet import *
from scapy.asn1fields import *

##########
## X509 ##
##########

######[ ASN1 class ]######

class ASN1_Class_X509(ASN1_Class_UNIVERSAL):
    name="X509"
    CONT0 = 0xa0
    CONT1 = 0xa1
    CONT2 = 0xa2
    CONT3 = 0xa3

class ASN1_X509_CONT0(ASN1_SEQUENCE):
    tag = ASN1_Class_X509.CONT0

class ASN1_X509_CONT1(ASN1_SEQUENCE):
    tag = ASN1_Class_X509.CONT1

class ASN1_X509_CONT2(ASN1_SEQUENCE):
    tag = ASN1_Class_X509.CONT2

class ASN1_X509_CONT3(ASN1_SEQUENCE):
    tag = ASN1_Class_X509.CONT3

######[ BER codecs ]#######

class BERcodec_X509_CONT0(BERcodec_SEQUENCE):
    tag = ASN1_Class_X509.CONT0

class BERcodec_X509_CONT1(BERcodec_SEQUENCE):
    tag = ASN1_Class_X509.CONT1
    
class BERcodec_X509_CONT2(BERcodec_SEQUENCE):
    tag = ASN1_Class_X509.CONT2
    
class BERcodec_X509_CONT3(BERcodec_SEQUENCE):
    tag = ASN1_Class_X509.CONT3

######[ ASN1 fields ]######

class ASN1F_X509_CONT0(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_X509.CONT0
    
class ASN1F_X509_CONT1(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_X509.CONT1
    
class ASN1F_X509_CONT2(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_X509.CONT2
    
class ASN1F_X509_CONT3(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_X509.CONT3

######[ X509 packets ]######

class X509RDN(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SET(
                  ASN1F_SEQUENCE( ASN1F_OID("oid","2.5.4.6"),
                                  ASN1F_PRINTABLE_STRING("value","")
                                  )
                  )

class X509v3Ext(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_field("val",ASN1_NULL(0))
    

class X509Cert(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_SEQUENCE(
            ASN1F_optionnal(ASN1F_X509_CONT0(ASN1F_INTEGER("version",3))),
            ASN1F_INTEGER("sn",1),
            ASN1F_SEQUENCE(ASN1F_OID("sign_algo","1.2.840.113549.1.1.5"),
                           ASN1F_field("sa_value",ASN1_NULL(0))),
            ASN1F_SEQUENCE_OF("issuer",[],X509RDN),
            ASN1F_SEQUENCE(ASN1F_UTC_TIME("not_before",ZuluTime(-600)),  # ten minutes ago
                           ASN1F_UTC_TIME("not_after",ZuluTime(+86400))), # for 24h
            ASN1F_SEQUENCE_OF("subject",[],X509RDN),
            ASN1F_SEQUENCE(
                ASN1F_SEQUENCE(ASN1F_OID("pubkey_algo","1.2.840.113549.1.1.1"),
                               ASN1F_field("pk_value",ASN1_NULL(0))),
                ASN1F_BIT_STRING("pubkey","")
                ),
            ASN1F_optionnal(ASN1F_X509_CONT3(ASN1F_SEQUENCE_OF("x509v3ext",[],X509v3Ext))),
            
        ),
        ASN1F_SEQUENCE(ASN1F_OID("sign_algo2","1.2.840.113549.1.1.5"),
                       ASN1F_field("sa2_value",ASN1_NULL(0))),
        ASN1F_BIT_STRING("signature","")
        )




