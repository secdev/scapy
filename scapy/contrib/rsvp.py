# RSVP layer

# http://trac.secdev.org/scapy/ticket/197

# scapy.contrib.description = RSVP
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import IP

rsvpmsgtypes = {0x01: "Path",
                0x02: "Reservation request",
                0x03: "Path error",
                0x04: "Reservation request error",
                0x05: "Path teardown",
                0x06: "Reservation teardown",
                0x07: "Reservation request acknowledgment"
                }


class RSVP(Packet):
    name = "RSVP"
    fields_desc = [BitField("Version", 1, 4),
                   BitField("Flags", 1, 4),
                   ByteEnumField("Class", 0x01, rsvpmsgtypes),
                   XShortField("chksum", None),
                   ByteField("TTL", 1),
                   XByteField("dataofs", 0),
                   ShortField("Length", None)]

    def post_build(self, p, pay):
        p += pay
        if self.Length is None:
            l = len(p)
            p = p[:6] + chr((l >> 8) & 0xff) + chr(l & 0xff) + p[8:]
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2] + chr(ck >> 8) + chr(ck & 0xff) + p[4:]
        return p

rsvptypes = {0x01: "Session",
             0x03: "HOP",
             0x04: "INTEGRITY",
             0x05: "TIME_VALUES",
             0x06: "ERROR_SPEC",
             0x07: "SCOPE",
             0x08:  "STYLE",
             0x09:  "FLOWSPEC",
             0x0A:  "FILTER_SPEC",
             0x0B:  "SENDER_TEMPLATE",
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
    name = "RSVP_Object"
    fields_desc = [ShortField("Length", 4),
                   ByteEnumField("Class", 0x01, rsvptypes),
                   ByteField("C-Type", 1)]

    def guess_payload_class(self, payload):
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
    name = "Data"
    fields_desc = [StrLenField(
        "Data", "", length_from=lambda pkt:pkt.underlayer.Length - 4)]

    def default_payload_class(self, payload):
        return RSVP_Object


class RSVP_HOP(Packet):
    name = "HOP"
    fields_desc = [IPField("neighbor", "0.0.0.0"),
                   BitField("inface", 1, 32)]

    def default_payload_class(self, payload):
        return RSVP_Object


class RSVP_Time(Packet):
    name = "Time Val"
    fields_desc = [BitField("refresh", 1, 32)]

    def default_payload_class(self, payload):
        return RSVP_Object


class RSVP_SenderTSPEC(Packet):
    name = "Sender_TSPEC"
    fields_desc = [ByteField("Msg_Format", 0),
                   ByteField("reserve", 0),
                   ShortField("Data_Length", 4),
                   ByteField("Srv_hdr", 1),
                   ByteField("reserve2", 0),
                   ShortField("Srv_Length", 4),
                   StrLenField("Tokens", "", length_from=lambda pkt:pkt.underlayer.Length - 12)]

    def default_payload_class(self, payload):
        return RSVP_Object


class RSVP_LabelReq(Packet):
    name = "Lable Req"
    fields_desc = [ShortField("reserve", 1),
                   ShortField("L3PID", 1)]

    def default_payload_class(self, payload):
        return RSVP_Object


class RSVP_SessionAttrb(Packet):
    name = "Session_Attribute"
    fields_desc = [ByteField("Setup_priority", 1),
                   ByteField("Hold_priority", 1),
                   ByteField("flags", 1),
                   ByteField("Name_length", 1),
                   StrLenField(
                       "Name", "", length_from=lambda pkt:pkt.underlayer.Length - 8),
                   ]

    def default_payload_class(self, payload):
        return RSVP_Object

bind_layers(IP,     RSVP,     {"proto": 46})
bind_layers(RSVP, RSVP_Object, {})
