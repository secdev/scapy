# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
RSVP layer
"""

# scapy.contrib.description = Resource Reservation Protocol (RSVP)
# scapy.contrib.status = loads

from scapy.compat import chb
from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteEnumField, ByteField, FieldLenField, \
    IPField, ShortField, StrLenField, XByteField, XShortField
from scapy.layers.inet import IP, checksum

rsvpmsgtypes = {0x01: "Path",
                0x02: "Reservation request",
                0x03: "Path error",
                0x04: "Reservation request error",
                0x05: "Path teardown",
                0x06: "Reservation teardown",
                0x07: "Reservation request acknowledgment"
                }


class RSVP(Packet):
    """Common RSVP message header.
    The header is followed by this message's RSVP objects, which in turn
    chains to further RSVP_Object instances (each object's data class returns
    RSVP_Object from default_payload_class), forming the sequence of RSVP objects.
    
    It contains the following fields:
        - Version: 4 bits, RSVP protocol version
        - Flags: 4 bits, RSVP message flags
        - Class: 8 bits, RSVP message type
        - chksum: 16 bits, computed over the whole message if None
        - TTL: 8 bits, IP TTL the message was sent with
        - dataofs: 8 bits, reserved
        - Length: 16 bits, total RSVP message length in bytes, computed if None
    """
    name = "RSVP"
    fields_desc = [BitField("Version", 1, 4),
                   BitField("Flags", 1, 4),
                   ByteEnumField("Class", 0x01, rsvpmsgtypes),
                   XShortField("chksum", None),
                   ByteField("TTL", 1),
                   XByteField("dataofs", 0),
                   ShortField("Length", None)]

    def post_build(self, p, pay):
        """Append payload bytes to the header, and patch in Length/checksum if unset.

        When the Length field is None, it gets computed.
        When the checksum is None, it gets computed.
        (The order of these two matters for correct checksum calculation)

        Returns the fully packet message bytes.
        """
        p += pay
        if self.Length is None:
            tmp_len = len(p)
            tmp_p = p[:6] + chb((tmp_len >> 8) & 0xff) + chb(tmp_len & 0xff)
            p = tmp_p + p[8:]
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2] + chb(ck >> 8) + chb(ck & 0xff) + p[4:]
        return p


rsvptypes = {0x01: "Session",
             0x03: "HOP",
             0x04: "INTEGRITY",
             0x05: "TIME_VALUES",
             0x06: "ERROR_SPEC",
             0x07: "SCOPE",
             0x08: "STYLE",
             0x09: "FLOWSPEC",
             0x0A: "FILTER_SPEC",
             0x0B: "SENDER_TEMPLATE",
             0x0C: "SENDER_TSPEC",
             0x0D: "ADSPEC",
             0x0E: "POLICY_DATA",
             0x0F: "RESV_CONFIRM",
             0x10: "RSVP_LABEL",
             0x11: "HOP_COUNT",
             0x12: "STRICT_SOURCE_ROUTE",
             0x13: "LABEL_REQUEST",
             0x14: "EXPLICIT_ROUTE",
             0x15: "ROUTE_RECORD",
             0x16: "HELLO",
             0x17: "MESSAGE_ID",
             0x18: "MESSAGE_ID_ACK",
             0x19: "MESSAGE_ID_LIST",
             0x1E: "DIAGNOSTIC",
             0x1F: "ROUTE",
             0x20: "DIAG_RESPONSE",
             0x21: "DIAG_SELECT",
             0x22: "RECOVERY_LABEL",
             0x23: "UPSTREAM_LABEL",
             0x24: "LABEL_SET",
             0x25: "PROTECTION",
             0x26: "PRIMARY PATH ROUTE",
             0x2A: "DSBM IP ADDRESS",
             0x2B: "SBM_PRIORITY",
             0x2C: "DSBM TIMER INTERVALS",
             0x2D: "SBM_INFO",
             0x32: "S2L_SUB_LSP",
             0x3F: "DETOUR",
             0x40: "CHALLENGE",
             0x41: "DIFF-SERV",
             0x42: "CLASSTYPE",
             0x43: "LSP_REQUIRED_ATTRIBUTES",
             0x80: "NODE_CHAR",
             0x81: "SUGGESTED_LABEL",
             0x82: "ACCEPTABLE_LABEL_SET",
             0x83: "RESTART_CA",
             0x84: "SESSION-OF-INTEREST",
             0x85: "LINK_CAPABILITY",
             0x86: "Capability Object",
             0xA1: "RSVP_HOP_L2",
             0xA2: "LAN_NHOP_L2",
             0xA3: "LAN_NHOP_L3",
             0xA4: "LAN_LOOPBACK",
             0xA5: "TCLASS",
             0xC0: "TUNNEL",
             0xC1: "LSP_TUNNEL_INTERFACE_ID",
             0xC2: "USER_ERROR_SPEC",
             0xC3: "NOTIFY_REQUEST",
             0xC4: "ADMIN-STATUS",
             0xC5: "LSP_ATTRIBUTES",
             0xC6: "ALARM_SPEC",
             0xC7: "ASSOCIATION",
             0xC8: "SECONDARY_EXPLICIT_ROUTE",
             0xC9: "SECONDARY_RECORD_ROUTE",
             0xCD: "FAST_REROUTE",
             0xCF: "SESSION_ATTRIBUTE",
             0xE1: "DCLASS",
             0xE2: "PACKETCABLE EXTENSIONS",
             0xE3: "ATM_SERVICECLASS",
             0xE4: "CALL_OPS (ASON)",
             0xE5: "GENERALIZED_UNI",
             0xE6: "CALL_ID",
             0xE7: "3GPP2_Object",
             0xE8: "EXCLUDE_ROUTE"
             }


class RSVP_Object(Packet):
    """Common RSVP object header.
    This header is followed by exacytly one RSVP object data structure,
    as chosen by the guess_payload_class method.
    Dissection naturally chains into the next object if more bytes remain.

    It contains the following fields:
        - Length: 16 bits, total length of this object including this header, computed if None.
        - Class: 8 bits, RSVP object type
        - C_Type: 8 bits, RSVP object subtype
    """
    name = "RSVP_Object"
    fields_desc = [ShortField("Length", 4),
                   ByteEnumField("Class", 0x01, rsvptypes),
                   ByteField("C_Type", 1)]

    def guess_payload_class(self, payload):
        """Pick the data class to dissect based on Class.
        
        Falls back to RSVP_data, a generic container for any Class value 
        that doesnt have a dedicated class yet.
        """
        if self.Class == 0x03:
            return RSVP_HOP
        elif self.Class == 0x05:
            return RSVP_Time
        elif self.Class == 0x0c:
            return RSVP_SenderTSPEC
        elif self.Class == 0x13:
            return RSVP_LabelReq
        elif self.Class == 0xCF:
            return RSVP_SessionAttrb
        else:
            return RSVP_Data


class RSVP_Data(Packet):
    """Defines a generic/unknown RSVP object data structure for any Class value 
    that doesnt have a dedicated class implemented yet.
    
    - overload_fields: Writes Class=0x01 back into the underlayer 
        RSVP_Object ONLY when this class is used to explicitly BUILD a packet
        (e.g. RSVP_Object()/RSVP_Data(...)) without the caller setting Class themselves. 
        (Note that this is just a pre-existing default Class value).
    
    - Data: raw bytes, whatever remains of this object after the 4-byte RSVP_Object header.
    """
    name = "Data"
    overload_fields = {RSVP_Object: {"Class": 0x01}}
    fields_desc = [StrLenField("Data", "", length_from=lambda pkt:pkt.underlayer.Length - 4)]  # noqa: E501

    def default_payload_class(self, payload):
        """Get the default payload class.
        Chains to another RSVP_Object if more bytes remain.
        """
        return RSVP_Object


class RSVP_HOP(Packet):
    """RSVP_HOP object data structure, RFC 2205 section A.2.

    Identifies the IP address and the Logical Interface Handle (LIH) 
    of the interface this message was sent from. 
    
    - neighbor: 32 bits, IP address of the interface this message was sent from.
    - inface: 32 bits, Logical Interface Handle (LIH) of the interface this message was sent from.
    """
    name = "HOP"
    overload_fields = {RSVP_Object: {"Class": 0x03}}
    fields_desc = [IPField("neighbor", "0.0.0.0"),
                   BitField("inface", 1, 32)]

    def default_payload_class(self, payload):
        """Get the default payload class.
        Chains to another RSVP_Object if more bytes remain.
        """
        return RSVP_Object


class RSVP_Time(Packet):
    """TIME_VALUES object RFC 2205 section A.4.
    Carries the refresh period a sender will use to resend PATH/RESV messages,
    which the receiver can use to determine when to tear down the reservation if no further messages are received.

    - refresh: 32 bits, refresh period in milliseconds.
    """
    name = "Time Val"
    overload_fields = {RSVP_Object: {"Class": 0x05}}
    fields_desc = [BitField("refresh", 1, 32)]

    def default_payload_class(self, payload):
        """Get the default payload class.
        Chains to another RSVP_Object if more bytes remain.
        """
        return RSVP_Object


class RSVP_SenderTSPEC(Packet):
    """SENDER_TSPEC object RFC 2210 section 3.1.

    Carries the sender's traffic specification for the reservation.

    - Msg_Format: 8 bits, message format.
    - reserve: 8 bits, reserved.
    - Data_Length: 16 bits, length of the data field.
    - Srv_hdr: 8 bits, service header.
    - reserve2: 8 bits, reserved.
    - Srv_Length: 16 bits, length of the service field.
    - Tokens: variable length, the encoded token-bucket parameters (r,b,p,m,M)
        and any further service specific data.
    """
    name = "Sender_TSPEC"
    overload_fields = {RSVP_Object: {"Class": 0x0c}}
    fields_desc = [ByteField("Msg_Format", 0),
                   ByteField("reserve", 0),
                   ShortField("Data_Length", 4),
                   ByteField("Srv_hdr", 1),
                   ByteField("reserve2", 0),
                   ShortField("Srv_Length", 4),
                   StrLenField(
                       "Tokens",
                       "",
                       length_from=lambda pkt:pkt.underlayer.Length - 12
                    )]

    def default_payload_class(self, payload):
        """Get the default payload class.
        Chains to another RSVP_Object if more bytes remain.
        """
        return RSVP_Object


class RSVP_LabelReq(Packet):
    """LABEL_REQUEST object RFC 3209 section 4.2.

    Requests that a label be allocated for this LSP, and indicates
    which layer 3 protocol the label will carry.

    - reserve: 16 bits, reserved.
    - L3PID: 16 bits, layer 3 protocol ID (e.g. 0x0800 for IPv4),
        identifying the payload type that will run over the established LSP.
    """
    name = "Label Req"
    overload_fields = {RSVP_Object: {"Class": 0x13}}
    fields_desc = [ShortField("reserve", 1),
                   ShortField("L3PID", 1)]

    def default_payload_class(self, payload):
        """Get the default payload class.
        Chains to another RSVP_Object if more bytes remain.
        """
        return RSVP_Object


class RSVP_SessionAttrb(Packet):
    """SESSION_ATTRIBUTE object RFC 3209 section 4.7.

    Carries session data, mainly used for setup/recovery 
    priority and human readable session name.

    - Setup_priority: 8 bits, setup priority for this session(can cause preemption).
    - Hold_priority: 8 bits, hold priority for this session(can be preempted).
    - flags: 8 bits, session attribute flags.
    - Name_length: 8 bits, length of the Name field in bytes.
    - Name: variable length, human readable session name.
    """
    name = "Session_Attribute"
    overload_fields = {RSVP_Object: {"Class": 0xCF}}
    fields_desc = [ByteField("Setup_priority", 1),
                   ByteField("Hold_priority", 1),
                   ByteField("flags", 1),
                   FieldLenField("Name_length", None, length_of="Name"),
                   StrLenField("Name", "", length_from=lambda pkt:pkt.Name_length),  # noqa: E501
                   ]

    def default_payload_class(self, payload):
        """Get the default payload class.
        Chains to another RSVP_Object if more bytes remain.
        """
        return RSVP_Object


# Decode IP packets with protocol number 46 as RSVP packets, and RSVP packets as RSVP_Object packets.
bind_layers(IP, RSVP, {"proto": 46})
bind_layers(RSVP, RSVP_Object)
