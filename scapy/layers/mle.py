# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) 2022 Dimitrios-Georgios Akestoridis <akestoridis@cmu.edu>
# This program is published under a GPLv2 license

"""
MLE (Mesh Link Establishment)
=============================

For more information, please refer to the following files:

* https://datatracker.ietf.org/doc/html/draft-ietf-6lo-mesh-link-establishment-00

* https://doi.org/10.1109/IEEESTD.2006.232110

* https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-mle.c

"""  # noqa: E501

from scapy.fields import (
    ByteEnumField,
    ConditionalField,
    PacketField,
    XStrField,
)
from scapy.layers.dot15d4 import Dot15d4AuxSecurityHeader
from scapy.layers.inet import UDP
from scapy.packet import (
    Packet,
    bind_layers,
)


class MLE(Packet):
    name = "Mesh Link Establishment"
    fields_desc = [
        ByteEnumField(
            "sec_suite",
            0,
            {
                0: "IEEE 802.15.4 Security (0)",
                255: "No Security (255)",
            },
        ),
        ConditionalField(
            PacketField(
                "aux_sec_header",
                Dot15d4AuxSecurityHeader(),
                Dot15d4AuxSecurityHeader,
            ),
            lambda pkt: pkt.sec_suite == 0,
        ),
        ConditionalField(
            XStrField("sec_payload", ""),
            lambda pkt: pkt.sec_suite == 0,
        ),
        ConditionalField(
            XStrField("mic", ""),
            lambda pkt: pkt.sec_suite == 0,
        ),
    ]

    def post_dissect(self, s):
        if self.sec_suite == 0:
            if self.aux_sec_header.sec_sc_seclevel in {1, 5}:
                mic_length = 4
            elif self.aux_sec_header.sec_sc_seclevel in {2, 6}:
                mic_length = 8
            elif self.aux_sec_header.sec_sc_seclevel in {3, 7}:
                mic_length = 16
            else:
                mic_length = 0
            self.sec_payload = bytes(self.aux_sec_header.payload)
            self.aux_sec_header.remove_payload()
            if mic_length > 0 and mic_length <= len(self.sec_payload):
                self.mic = self.sec_payload[-mic_length:]
                self.sec_payload = self.sec_payload[:-mic_length]
        return s

    def guess_payload_class(self, payload):
        if self.sec_suite == 255:
            return MLECmd
        return Packet.guess_payload_class(self, payload)


class MLECmd(Packet):
    name = "Mesh Link Establishment Command"
    fields_desc = [
        ByteEnumField(
            "cmd_type",
            0,
            {
                0: "Link Request (0)",
                1: "Link Accept (1)",
                2: "Link Accept and Request (2)",
                3: "Link Reject (3)",
                4: "Advertisement (4)",
                5: "Update (5)",
                6: "Update Request (6)",
                7: "Data Request (7)",
                8: "Data Response (8)",
                9: "Parent Request (9)",
                10: "Parent Response (10)",
                11: "Child ID Request (11)",
                12: "Child ID Response (12)",
                13: "Child Update Request (13)",
                14: "Child Update Response (14)",
                15: "Announce (15)",
                16: "Discovery Request (16)",
                17: "Discovery Response (17)",
            },
        ),
        # TODO: Dissect the command payload
    ]


bind_layers(UDP, MLE, sport=19788, dport=19788)
