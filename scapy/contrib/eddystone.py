# -*- mode: python3; indent-tabs-mode: nil; tab-width: 4 -*-
# eddystone.py - protocol handlers for Eddystone beacons
#
# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Michael Farrell <micolous+git@gmail.com>
# This program is published under a GPLv2 (or later) license
#
# The Eddystone specification can be found at:
# https://github.com/google/eddystone/blob/master/protocol-specification.md
#
# scapy.contrib.description = Eddystone BLE proximity beacon
# scapy.contrib.status = loads

from scapy.compat import orb
from scapy.packet import bind_layers, Packet
from scapy.fields import IntField, SignedByteField, StrField, BitField, \
    StrFixedLenField, ShortField, FixedPointField, ByteEnumField
from scapy.layers.bluetooth import EIR_Hdr, EIR_ServiceData16BitUUID, \
    EIR_Flags, EIR_CompleteList16BitServiceUUIDs, HCI_Hdr, HCI_Command_Hdr, \
    HCI_Cmd_LE_Set_Advertising_Data, HCI_LE_Meta_Advertising_Report
from scapy.modules import six

EDDYSTONE_UUID = 0xfeaa

EDDYSTONE_URL_SCHEMES = {
    0: b"http://www.",
    1: b"https://www.",
    2: b"http://",
    3: b"https://",
}

EDDYSTONE_URL_TABLE = {
    0: b".com/",
    1: b".org/",
    2: b".edu/",
    3: b".net/",
    4: b".info/",
    5: b".biz/",
    6: b".gov/",
    7: b".com",
    8: b".org",
    9: b".edu",
    10: b".net",
    11: b".info",
    12: b".biz",
    13: b".gov",
}


class EddystoneURLField(StrField):
    # https://github.com/google/eddystone/tree/master/eddystone-url#eddystone-url-http-url-encoding
    def i2m(self, pkt, x):
        if x is None:
            return b""

        o = bytearray()
        p = 0
        while p < len(x):
            c = orb(x[p])
            if c == 46:  # "."
                for k, v in EDDYSTONE_URL_TABLE.items():
                    if x.startswith(v, p):
                        o.append(k)
                        p += len(v) - 1
                        break
                else:
                    o.append(c)
            else:
                o.append(c)
            p += 1

        # Make the output immutable.
        return bytes(o)

    def m2i(self, pkt, x):
        if not x:
            return None

        o = bytearray()
        for c in x:
            i = orb(c)
            r = EDDYSTONE_URL_TABLE.get(i)
            if r is None:
                o.append(i)
            else:
                o.extend(r)
        return bytes(o)

    def any2i(self, pkt, x):
        if isinstance(x, six.text_type):
            x = x.encode("ascii")
        return x


class Eddystone_Frame(Packet):
    # https://github.com/google/eddystone/blob/master/protocol-specification.md
    name = "Eddystone Frame"
    fields_desc = [
        BitField("type", None, 4),
        BitField("reserved", 0, 4),
    ]

    def build_eir(self):
        """Builds a list of EIR messages to wrap this frame."""

        return [
            EIR_Hdr() / EIR_Flags(flags=[
                "general_disc_mode", "br_edr_not_supported"]),
            EIR_Hdr() / EIR_CompleteList16BitServiceUUIDs(svc_uuids=[
                EDDYSTONE_UUID]),
            EIR_Hdr() / EIR_ServiceData16BitUUID() / self
        ]

    def build_advertising_report(self):
        """Builds HCI_LE_Meta_Advertising_Report containing this frame."""

        return HCI_LE_Meta_Advertising_Report(
            type=0,   # Undirected
            atype=1,  # Random address
            data=self.build_eir()
        )

    def build_set_advertising_data(self):
        """Builds a HCI_Cmd_LE_Set_Advertising_Data containing this frame.

        This includes the HCI_Hdr and HCI_Command_Hdr layers.
        """

        return HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_LE_Set_Advertising_Data(
            data=self.build_eir()
        )


class Eddystone_UID(Packet):
    # https://github.com/google/eddystone/tree/master/eddystone-uid
    name = "Eddystone UID"
    fields_desc = [
        SignedByteField("tx_power", 0),
        StrFixedLenField("namespace", None, 10),
        StrFixedLenField("instance", None, 6),
        StrFixedLenField("reserved", None, 2),
    ]


class Eddystone_URL(Packet):
    # https://github.com/google/eddystone/tree/master/eddystone-url
    name = "Eddystone URL"
    fields_desc = [
        SignedByteField("tx_power", 0),
        ByteEnumField("url_scheme", 0, EDDYSTONE_URL_SCHEMES),
        EddystoneURLField("url", None),
    ]

    def to_url(self):
        return EDDYSTONE_URL_SCHEMES[self.url_scheme] + self.url

    @staticmethod
    def from_url(url):
        """Creates an Eddystone_Frame with a Eddystone_URL for a given URL."""
        url = url.encode('ascii')
        scheme = None
        for k, v in EDDYSTONE_URL_SCHEMES.items():
            if url.startswith(v):
                scheme = k
                url = url[len(v):]
                break
        else:
            raise Exception("URLs must start with EDDYSTONE_URL_SCHEMES")

        return Eddystone_Frame() / Eddystone_URL(
            url_scheme=scheme,
            url=url)


class Eddystone_TLM(Packet):
    # https://github.com/google/eddystone/tree/master/eddystone-tlm
    name = "Eddystone TLM"
    fields_desc = [
        ByteEnumField("version", None, {
            0: "unencrypted",
            1: "encrypted",
        }),
    ]


class Eddystone_TLM_Unencrypted(Packet):
    # https://github.com/google/eddystone/blob/master/eddystone-tlm/tlm-plain.md
    name = "Eddystone TLM (Unencrypted)"
    fields_desc = [
        ShortField("batt_mv", 0),
        FixedPointField("temperature", -128, 16, 8),
        IntField("adv_cnt", None),
        IntField("sec_cnt", None),
    ]


class Eddystone_TLM_Encrypted(Packet):
    # https://github.com/google/eddystone/blob/master/eddystone-tlm/tlm-encrypted.md
    name = "Eddystone TLM (Encrypted)"
    fields_desc = [
        StrFixedLenField("etlm", None, 12),
        StrFixedLenField("salt", None, 2),
        StrFixedLenField("mic", None, 2),
    ]


class Eddystone_EID(Packet):
    # https://github.com/google/eddystone/tree/master/eddystone-eid
    name = "Eddystone EID"
    fields_desc = [
        SignedByteField("tx_power", 0),
        StrFixedLenField("eid", None, 8),
    ]


bind_layers(Eddystone_TLM, Eddystone_TLM_Unencrypted, version=0)
bind_layers(Eddystone_TLM, Eddystone_TLM_Encrypted, version=1)

bind_layers(Eddystone_Frame, Eddystone_UID, type=0)
bind_layers(Eddystone_Frame, Eddystone_URL, type=1)
bind_layers(Eddystone_Frame, Eddystone_TLM, type=2)
bind_layers(Eddystone_Frame, Eddystone_EID, type=3)

bind_layers(EIR_ServiceData16BitUUID, Eddystone_Frame, svc_uuid=EDDYSTONE_UUID)
