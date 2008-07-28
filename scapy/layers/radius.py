## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

import struct
from scapy.packet import *
from scapy.fields import *

class Radius(Packet):
    name = "Radius"
    fields_desc = [ ByteEnumField("code", 1, {1: "Access-Request",
                                              2: "Access-Accept",
                                              3: "Access-Reject",
                                              4: "Accounting-Request",
                                              5: "Accounting-Accept",
                                              6: "Accounting-Status",
                                              7: "Password-Request",
                                              8: "Password-Ack",
                                              9: "Password-Reject",
                                              10: "Accounting-Message",
                                              11: "Access-Challenge",
                                              12: "Status-Server",
                                              13: "Status-Client",
                                              21: "Resource-Free-Request",
                                              22: "Resource-Free-Response",
                                              23: "Resource-Query-Request",
                                              24: "Resource-Query-Response",
                                              25: "Alternate-Resource-Reclaim-Request",
                                              26: "NAS-Reboot-Request",
                                              27: "NAS-Reboot-Response",
                                              29: "Next-Passcode",
                                              30: "New-Pin",
                                              31: "Terminate-Session",
                                              32: "Password-Expired",
                                              33: "Event-Request",
                                              34: "Event-Response",
                                              40: "Disconnect-Request",
                                              41: "Disconnect-ACK",
                                              42: "Disconnect-NAK",
                                              43: "CoA-Request",
                                              44: "CoA-ACK",
                                              45: "CoA-NAK",
                                              50: "IP-Address-Allocate",
                                              51: "IP-Address-Release",
                                              253: "Experimental-use",
                                              254: "Reserved",
                                              255: "Reserved"} ),
                    ByteField("id", 0),
                    ShortField("len", None),
                    StrFixedLenField("authenticator","",16) ]
    def post_build(self, p, pay):
        p += pay
        l = self.len
        if l is None:
            l = len(p)
            p = p[:2]+struct.pack("!H",l)+p[4:]
        return p



