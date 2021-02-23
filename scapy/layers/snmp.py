# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
SNMP (Simple Network Management Protocol).
"""

from __future__ import print_function
from scapy.packet import bind_layers, bind_bottom_up
from scapy.asn1packet import ASN1_Packet
from scapy.asn1fields import ASN1F_INTEGER, ASN1F_IPADDRESS, ASN1F_OID, \
    ASN1F_SEQUENCE, ASN1F_SEQUENCE_OF, ASN1F_STRING, ASN1F_TIME_TICKS, \
    ASN1F_enum_INTEGER, ASN1F_field, ASN1F_CHOICE
from scapy.asn1.asn1 import ASN1_Class_UNIVERSAL, ASN1_Codecs, ASN1_NULL, \
    ASN1_SEQUENCE
from scapy.asn1.ber import BERcodec_SEQUENCE
from scapy.sendrecv import sr1
from scapy.volatile import RandShort, IntAutoTime
from scapy.layers.inet import UDP, IP, ICMP

# Import needed to initialize conf.mib
from scapy.asn1.mib import conf  # noqa: F401

##########
#  SNMP  #
##########

#     [ ASN1 class ]     #


class ASN1_Class_SNMP(ASN1_Class_UNIVERSAL):
    name = "SNMP"
    PDU_GET = 0xa0
    PDU_NEXT = 0xa1
    PDU_RESPONSE = 0xa2
    PDU_SET = 0xa3
    PDU_TRAPv1 = 0xa4
    PDU_BULK = 0xa5
    PDU_INFORM = 0xa6
    PDU_TRAPv2 = 0xa7


class ASN1_SNMP_PDU_GET(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_GET


class ASN1_SNMP_PDU_NEXT(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_NEXT


class ASN1_SNMP_PDU_RESPONSE(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_RESPONSE


class ASN1_SNMP_PDU_SET(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_SET


class ASN1_SNMP_PDU_TRAPv1(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv1


class ASN1_SNMP_PDU_BULK(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_BULK


class ASN1_SNMP_PDU_INFORM(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_INFORM


class ASN1_SNMP_PDU_TRAPv2(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv2


#     [ BER codecs ]      #

class BERcodec_SNMP_PDU_GET(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_GET


class BERcodec_SNMP_PDU_NEXT(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_NEXT


class BERcodec_SNMP_PDU_RESPONSE(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_RESPONSE


class BERcodec_SNMP_PDU_SET(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_SET


class BERcodec_SNMP_PDU_TRAPv1(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv1


class BERcodec_SNMP_PDU_BULK(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_BULK


class BERcodec_SNMP_PDU_INFORM(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_INFORM


class BERcodec_SNMP_PDU_TRAPv2(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv2


#     [ ASN1 fields ]     #

class ASN1F_SNMP_PDU_GET(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_GET


class ASN1F_SNMP_PDU_NEXT(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_NEXT


class ASN1F_SNMP_PDU_RESPONSE(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_RESPONSE


class ASN1F_SNMP_PDU_SET(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_SET


class ASN1F_SNMP_PDU_TRAPv1(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_TRAPv1


class ASN1F_SNMP_PDU_BULK(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_BULK


class ASN1F_SNMP_PDU_INFORM(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_INFORM


class ASN1F_SNMP_PDU_TRAPv2(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_TRAPv2


#     [ SNMP Packet ]     #


SNMP_error = {0: "no_error",
              1: "too_big",
              2: "no_such_name",
              3: "bad_value",
              4: "read_only",
              5: "generic_error",
              6: "no_access",
              7: "wrong_type",
              8: "wrong_length",
              9: "wrong_encoding",
              10: "wrong_value",
              11: "no_creation",
              12: "inconsistent_value",
              13: "resource_unavailable",
              14: "commit_failed",
              15: "undo_failed",
              16: "authorization_error",
              17: "not_writable",
              18: "inconsistent_name",
              }

SNMP_trap_types = {0: "cold_start",
                   1: "warm_start",
                   2: "link_down",
                   3: "link_up",
                   4: "auth_failure",
                   5: "egp_neigh_loss",
                   6: "enterprise_specific",
                   }


class SNMPvarbind(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(ASN1F_OID("oid", "1.3"),
                               ASN1F_field("value", ASN1_NULL(0))
                               )


class SNMPget(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_GET(ASN1F_INTEGER("id", 0),
                                   ASN1F_enum_INTEGER("error", 0, SNMP_error),
                                   ASN1F_INTEGER("error_index", 0),
                                   ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)  # noqa: E501
                                   )


class SNMPnext(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_NEXT(ASN1F_INTEGER("id", 0),
                                    ASN1F_enum_INTEGER("error", 0, SNMP_error),
                                    ASN1F_INTEGER("error_index", 0),
                                    ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)  # noqa: E501
                                    )


class SNMPresponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_RESPONSE(ASN1F_INTEGER("id", 0),
                                        ASN1F_enum_INTEGER("error", 0, SNMP_error),  # noqa: E501
                                        ASN1F_INTEGER("error_index", 0),
                                        ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)  # noqa: E501
                                        )


class SNMPset(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_SET(ASN1F_INTEGER("id", 0),
                                   ASN1F_enum_INTEGER("error", 0, SNMP_error),
                                   ASN1F_INTEGER("error_index", 0),
                                   ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)  # noqa: E501
                                   )


class SNMPtrapv1(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_TRAPv1(ASN1F_OID("enterprise", "1.3"),
                                      ASN1F_IPADDRESS("agent_addr", "0.0.0.0"),
                                      ASN1F_enum_INTEGER("generic_trap", 0, SNMP_trap_types),  # noqa: E501
                                      ASN1F_INTEGER("specific_trap", 0),
                                      ASN1F_TIME_TICKS("time_stamp", IntAutoTime()),  # noqa: E501
                                      ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)  # noqa: E501
                                      )


class SNMPbulk(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_BULK(ASN1F_INTEGER("id", 0),
                                    ASN1F_INTEGER("non_repeaters", 0),
                                    ASN1F_INTEGER("max_repetitions", 0),
                                    ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)  # noqa: E501
                                    )


class SNMPinform(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_INFORM(ASN1F_INTEGER("id", 0),
                                      ASN1F_enum_INTEGER("error", 0, SNMP_error),  # noqa: E501
                                      ASN1F_INTEGER("error_index", 0),
                                      ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)  # noqa: E501
                                      )


class SNMPtrapv2(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_TRAPv2(ASN1F_INTEGER("id", 0),
                                      ASN1F_enum_INTEGER("error", 0, SNMP_error),  # noqa: E501
                                      ASN1F_INTEGER("error_index", 0),
                                      ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)  # noqa: E501
                                      )


class SNMP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("version", 1, {0: "v1", 1: "v2c", 2: "v2", 3: "v3"}),  # noqa: E501
        ASN1F_STRING("community", "public"),
        ASN1F_CHOICE("PDU", SNMPget(),
                     SNMPget, SNMPnext, SNMPresponse, SNMPset,
                     SNMPtrapv1, SNMPbulk, SNMPinform, SNMPtrapv2)
    )

    def answers(self, other):
        return (isinstance(self.PDU, SNMPresponse) and
                isinstance(other.PDU, (SNMPget, SNMPnext, SNMPset)) and
                self.PDU.id == other.PDU.id)


bind_bottom_up(UDP, SNMP, sport=161)
bind_bottom_up(UDP, SNMP, dport=161)
bind_bottom_up(UDP, SNMP, sport=162)
bind_bottom_up(UDP, SNMP, dport=162)
bind_layers(UDP, SNMP, sport=161, dport=161)


def snmpwalk(dst, oid="1", community="public"):
    try:
        while True:
            r = sr1(IP(dst=dst) / UDP(sport=RandShort()) / SNMP(community=community, PDU=SNMPnext(varbindlist=[SNMPvarbind(oid=oid)])), timeout=2, chainCC=1, verbose=0, retry=2)  # noqa: E501
            if r is None:
                print("No answers")
                break
            if ICMP in r:
                print(repr(r))
                break
            print("%-40s: %r" % (r[SNMPvarbind].oid.val, r[SNMPvarbind].value))
            oid = r[SNMPvarbind].oid

    except KeyboardInterrupt:
        pass
