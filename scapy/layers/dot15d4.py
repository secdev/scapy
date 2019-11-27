# This program is published under a GPLv2 license
# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Ryan Speers <ryan@rmspeers.com> 2011-2012
# Copyright (C) Roger Meyer <roger.meyer@csus.edu>: 2012-03-10 Added frames
# Copyright (C) Gabriel Potter <gabriel@potter.fr>: 2018
# Intern at INRIA Grand Nancy Est
# This program is published under a GPLv2 license

"""
Wireless MAC according to IEEE 802.15.4.
"""

import struct

from scapy.compat import orb, chb
from scapy.error import warning
from scapy.config import conf

from scapy.data import DLT_IEEE802_15_4_WITHFCS, DLT_IEEE802_15_4_NOFCS
from scapy.packet import Packet, bind_layers
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    ConditionalField, Field, LELongField, PacketField, XByteField, \
    XLEIntField, XLEShortField, FCSField, Emph

# Fields #


class dot15d4AddressField(Field):
    __slots__ = ["adjust", "length_of"]

    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of
        if adjust is not None:
            self.adjust = adjust
        else:
            self.adjust = lambda pkt, x: self.lengthFromAddrMode(pkt, x)

    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        if len(hex(self.i2m(pkt, x))) < 7:  # short address
            return hex(self.i2m(pkt, x))
        else:  # long address
            x = "%016x" % self.i2m(pkt, x)
            return ":".join(["%s%s" % (x[i], x[i + 1]) for i in range(0, len(x), 2)])  # noqa: E501

    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.adjust(pkt, self.length_of) == 2:
            return s + struct.pack(self.fmt[0] + "H", val)
        elif self.adjust(pkt, self.length_of) == 8:
            return s + struct.pack(self.fmt[0] + "Q", val)
        else:
            return s

    def getfield(self, pkt, s):
        if self.adjust(pkt, self.length_of) == 2:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0] + "H", s[:2])[0])  # noqa: E501
        elif self.adjust(pkt, self.length_of) == 8:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0] + "Q", s[:8])[0])  # noqa: E501
        else:
            raise Exception('impossible case')

    def lengthFromAddrMode(self, pkt, x):
        addrmode = 0
        pkttop = pkt.underlayer
        if pkttop is None:
            warning("No underlayer to guess address mode")
            return 0
        while True:
            try:
                addrmode = pkttop.getfieldval(x)
                break
            except Exception:
                if pkttop.underlayer is None:
                    break
                pkttop = pkttop.underlayer
        # print "Underlayer field value of", x, "is", addrmode
        if addrmode == 2:
            return 2
        elif addrmode == 3:
            return 8
        return 0


# Layers #

class Dot15d4(Packet):
    name = "802.15.4"
    fields_desc = [
        BitField("fcf_reserved_1", 0, 1),  # fcf p1 b1
        BitEnumField("fcf_panidcompress", 0, 1, [False, True]),
        BitEnumField("fcf_ackreq", 0, 1, [False, True]),
        BitEnumField("fcf_pending", 0, 1, [False, True]),
        BitEnumField("fcf_security", 0, 1, [False, True]),  # fcf p1 b2
        Emph(BitEnumField("fcf_frametype", 0, 3, {0: "Beacon", 1: "Data", 2: "Ack", 3: "Command"})),  # noqa: E501
        BitEnumField("fcf_srcaddrmode", 0, 2, {0: "None", 1: "Reserved", 2: "Short", 3: "Long"}),  # fcf p2 b1  # noqa: E501
        BitField("fcf_framever", 0, 2),  # 00 compatibility with 2003 version; 01 compatible with 2006 version  # noqa: E501
        BitEnumField("fcf_destaddrmode", 2, 2, {0: "None", 1: "Reserved", 2: "Short", 3: "Long"}),  # fcf p2 b2  # noqa: E501
        BitField("fcf_reserved_2", 0, 2),
        Emph(ByteField("seqnum", 1))  # sequence number
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 %Dot15d4.fcf_frametype% ackreq(%Dot15d4.fcf_ackreq%) ( %Dot15d4.fcf_destaddrmode% -> %Dot15d4.fcf_srcaddrmode% ) Seq#%Dot15d4.seqnum%")  # noqa: E501

    def guess_payload_class(self, payload):
        if self.fcf_frametype == 0x00:
            return Dot15d4Beacon
        elif self.fcf_frametype == 0x01:
            return Dot15d4Data
        elif self.fcf_frametype == 0x02:
            return Dot15d4Ack
        elif self.fcf_frametype == 0x03:
            return Dot15d4Cmd
        else:
            return Packet.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, Dot15d4):
            if self.fcf_frametype == 2:  # ack
                if self.seqnum != other.seqnum:  # check for seqnum matching
                    return 0
                elif other.fcf_ackreq == 1:  # check that an ack was indeed requested  # noqa: E501
                    return 1
        return 0

    def post_build(self, p, pay):
        # This just forces destaddrmode to None for Ack frames.
        if self.fcf_frametype == 2 and self.fcf_destaddrmode != 0:
            self.fcf_destaddrmode = 0
            return p[:1] + \
                chb((self.fcf_srcaddrmode << 6) + (self.fcf_framever << 4)) \
                + p[2:] + pay
        else:
            return p + pay


class Dot15d4FCS(Dot15d4):
    '''
    This class is a drop-in replacement for the Dot15d4 class above, except
    it expects a FCS/checksum in the input, and produces one in the output.
    This provides the user flexibility, as many 802.15.4 interfaces will have an AUTO_CRC setting  # noqa: E501
    that will validate the FCS/CRC in firmware, and add it automatically when transmitting.  # noqa: E501
    '''
    name = "802.15.4 - FCS"
    match_subclass = True
    fields_desc = Dot15d4.fields_desc + [FCSField("fcs", None, fmt="<H")]

    def compute_fcs(self, data):
        # Do a CRC-CCITT Kermit 16bit on the data given
        # Returns a CRC that is the FCS for the frame
        #  Implemented using pseudocode from: June 1986, Kermit Protocol Manual
        #  See also:
        #   http://regregex.bbcmicro.net/crc-catalogue.htm#crc.cat.kermit
        crc = 0
        for i in range(0, len(data)):
            c = orb(data[i])
            q = (crc ^ c) & 15  # Do low-order 4 bits
            crc = (crc // 16) ^ (q * 4225)
            q = (crc ^ (c // 16)) & 15  # And high 4 bits
            crc = (crc // 16) ^ (q * 4225)
        return struct.pack('<H', crc)  # return as bytes in little endian order

    def post_build(self, p, pay):
        # construct the packet with the FCS at the end
        p = Dot15d4.post_build(self, p, pay)
        if self.fcs is None:
            p = p[:-2]
            p = p + self.compute_fcs(p)
        return p


class Dot15d4Ack(Packet):
    name = "802.15.4 Ack"
    fields_desc = []


class Dot15d4AuxSecurityHeader(Packet):
    name = "802.15.4 Auxiliary Security Header"
    fields_desc = [
        BitField("sec_sc_reserved", 0, 3),
        # Key Identifier Mode
        # 0: Key is determined implicitly from the originator and recipient(s) of the frame  # noqa: E501
        # 1: Key is determined explicitly from the the 1-octet Key Index subfield of the Key Identifier field  # noqa: E501
        # 2: Key is determined explicitly from the 4-octet Key Source and the 1-octet Key Index  # noqa: E501
        # 3: Key is determined explicitly from the 8-octet Key Source and the 1-octet Key Index  # noqa: E501
        BitEnumField("sec_sc_keyidmode", 0, 2, {
            0: "Implicit", 1: "1oKeyIndex", 2: "4o-KeySource-1oKeyIndex", 3: "8o-KeySource-1oKeyIndex"}  # noqa: E501
        ),
        BitEnumField("sec_sc_seclevel", 0, 3, {0: "None", 1: "MIC-32", 2: "MIC-64", 3: "MIC-128", 4: "ENC", 5: "ENC-MIC-32", 6: "ENC-MIC-64", 7: "ENC-MIC-128"}),  # noqa: E501
        XLEIntField("sec_framecounter", 0x00000000),  # 4 octets
        # Key Identifier (variable length): identifies the key that is used for cryptographic protection  # noqa: E501
        # Key Source : length of sec_keyid_keysource varies btwn 0, 4, and 8 bytes depending on sec_sc_keyidmode  # noqa: E501
        # 4 octets when sec_sc_keyidmode == 2
        ConditionalField(XLEIntField("sec_keyid_keysource", 0x00000000),
                         lambda pkt: pkt.getfieldval("sec_sc_keyidmode") == 2),
        # 8 octets when sec_sc_keyidmode == 3
        ConditionalField(LELongField("sec_keyid_keysource", 0x0000000000000000),  # noqa: E501
                         lambda pkt: pkt.getfieldval("sec_sc_keyidmode") == 3),
        # Key Index (1 octet): allows unique identification of different keys with the same originator  # noqa: E501
        ConditionalField(XByteField("sec_keyid_keyindex", 0xFF),
                         lambda pkt: pkt.getfieldval("sec_sc_keyidmode") != 0),
    ]


class Dot15d4Data(Packet):
    name = "802.15.4 Data"
    fields_desc = [
        XLEShortField("dest_panid", 0xFFFF),
        dot15d4AddressField("dest_addr", 0xFFFF, length_of="fcf_destaddrmode"),
        ConditionalField(XLEShortField("src_panid", 0x0),
                         lambda pkt:util_srcpanid_present(pkt)),
        ConditionalField(dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),  # noqa: E501
        # Security field present if fcf_security == True
        ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_security") is True),  # noqa: E501
    ]

    def guess_payload_class(self, payload):
        # TODO: See how it's done in wireshark:
        # https://github.com/wireshark/wireshark/blob/93c60b3b7c801dddd11d8c7f2a0ea4b7d02d700a/epan/dissectors/packet-ieee802154.c#L2061  # noqa: E501
        # it's too magic to me
        from scapy.layers.sixlowpan import SixLoWPAN
        from scapy.layers.zigbee import ZigbeeNWK
        if conf.dot15d4_protocol == "sixlowpan":
            return SixLoWPAN
        elif conf.dot15d4_protocol == "zigbee":
            return ZigbeeNWK
        else:
            if conf.dot15d4_protocol is None:
                _msg = "Please set conf.dot15d4_protocol to select a " + \
                       "802.15.4 protocol. Values must be in the list: "
            else:
                _msg = "Unknown conf.dot15d4_protocol value: must be in "
            warning(_msg +
                    "['sixlowpan', 'zigbee']" +
                    " Defaulting to SixLoWPAN")
            return SixLoWPAN

    def mysummary(self):
        return self.sprintf("802.15.4 Data ( %Dot15d4Data.src_panid%:%Dot15d4Data.src_addr% -> %Dot15d4Data.dest_panid%:%Dot15d4Data.dest_addr% )")  # noqa: E501


class Dot15d4Beacon(Packet):
    name = "802.15.4 Beacon"
    fields_desc = [
        XLEShortField("src_panid", 0x0),
        dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"),
        # Security field present if fcf_security == True
        ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_security") is True),  # noqa: E501

        # Superframe spec field:
        BitField("sf_sforder", 15, 4),  # not used by ZigBee
        BitField("sf_beaconorder", 15, 4),  # not used by ZigBee
        BitEnumField("sf_assocpermit", 0, 1, [False, True]),
        BitEnumField("sf_pancoord", 0, 1, [False, True]),
        BitField("sf_reserved", 0, 1),  # not used by ZigBee
        BitEnumField("sf_battlifeextend", 0, 1, [False, True]),  # not used by ZigBee  # noqa: E501
        BitField("sf_finalcapslot", 15, 4),  # not used by ZigBee

        # GTS Fields
        #  GTS Specification (1 byte)
        BitEnumField("gts_spec_permit", 1, 1, [False, True]),  # GTS spec bit 7, true=1 iff PAN cord is accepting GTS requests  # noqa: E501
        BitField("gts_spec_reserved", 0, 4),  # GTS spec bits 3-6
        BitField("gts_spec_desccount", 0, 3),  # GTS spec bits 0-2
        #  GTS Directions (0 or 1 byte)
        ConditionalField(BitField("gts_dir_reserved", 0, 1), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),  # noqa: E501
        ConditionalField(BitField("gts_dir_mask", 0, 7), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),  # noqa: E501
        #  GTS List (variable size)
        # TODO add a Packet/FieldListField tied to 3bytes per count in gts_spec_desccount  # noqa: E501

        # Pending Address Fields:
        #  Pending Address Specification (1 byte)
        BitField("pa_num_short", 0, 3),  # number of short addresses pending
        BitField("pa_reserved_1", 0, 1),
        BitField("pa_num_long", 0, 3),  # number of long addresses pending
        BitField("pa_reserved_2", 0, 1),
        #  Address List (var length)
        # TODO add a FieldListField of the pending short addresses, followed by the pending long addresses, with max 7 addresses  # noqa: E501
        # TODO beacon payload
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Beacon ( %Dot15d4Beacon.src_panid%:%Dot15d4Beacon.src_addr% ) assocPermit(%Dot15d4Beacon.sf_assocpermit%) panCoord(%Dot15d4Beacon.sf_pancoord%)")  # noqa: E501


class Dot15d4Cmd(Packet):
    name = "802.15.4 Command"
    fields_desc = [
        XLEShortField("dest_panid", 0xFFFF),
        # Users should correctly set the dest_addr field. By default is 0x0 for construction to work.  # noqa: E501
        dot15d4AddressField("dest_addr", 0x0, length_of="fcf_destaddrmode"),
        ConditionalField(XLEShortField("src_panid", 0x0), \
                         lambda pkt:util_srcpanid_present(pkt)),
        ConditionalField(dot15d4AddressField("src_addr", None,
                         length_of="fcf_srcaddrmode"),
                         lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),  # noqa: E501
        # Security field present if fcf_security == True
        ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),  # noqa: E501
                         lambda pkt:pkt.underlayer.getfieldval("fcf_security") is True),  # noqa: E501
        ByteEnumField("cmd_id", 0, {
            1: "AssocReq",  # Association request
            2: "AssocResp",  # Association response
            3: "DisassocNotify",  # Disassociation notification
            4: "DataReq",  # Data request
            5: "PANIDConflictNotify",  # PAN ID conflict notification
            6: "OrphanNotify",  # Orphan notification
            7: "BeaconReq",  # Beacon request
            8: "CoordRealign",  # coordinator realignment
            9: "GTSReq"  # GTS request
            # 0x0a - 0xff reserved
        }),
        # TODO command payload
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Command %Dot15d4Cmd.cmd_id% ( %Dot15dCmd.src_panid%:%Dot15d4Cmd.src_addr% -> %Dot15d4Cmd.dest_panid%:%Dot15d4Cmd.dest_addr% )")  # noqa: E501

    # command frame payloads are complete: DataReq, PANIDConflictNotify, OrphanNotify, BeaconReq don't have any payload  # noqa: E501
    # Although BeaconReq can have an optional ZigBee Beacon payload (implemented in ZigBeeBeacon)  # noqa: E501
    def guess_payload_class(self, payload):
        if self.cmd_id == 1:
            return Dot15d4CmdAssocReq
        elif self.cmd_id == 2:
            return Dot15d4CmdAssocResp
        elif self.cmd_id == 3:
            return Dot15d4CmdDisassociation
        elif self.cmd_id == 8:
            return Dot15d4CmdCoordRealign
        elif self.cmd_id == 9:
            return Dot15d4CmdGTSReq
        else:
            return Packet.guess_payload_class(self, payload)


class Dot15d4CmdCoordRealign(Packet):
    name = "802.15.4 Coordinator Realign Command"
    fields_desc = [
        # PAN Identifier (2 octets)
        XLEShortField("panid", 0xFFFF),
        # Coordinator Short Address (2 octets)
        XLEShortField("coord_address", 0x0000),
        # Logical Channel (1 octet): the logical channel that the coordinator intends to use for all future communications  # noqa: E501
        ByteField("channel", 0),
        # Short Address (2 octets)
        XLEShortField("dev_address", 0xFFFF),
        # Channel page (0/1 octet) TODO optional
        # ByteField("channel_page", 0),
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Coordinator Realign Payload ( PAN ID: %Dot15dCmdCoordRealign.pan_id% : channel %Dot15d4CmdCoordRealign.channel% )")  # noqa: E501


# Utility Functions #


def util_srcpanid_present(pkt):
    '''A source PAN ID is included if and only if both src addr mode != 0 and PAN ID Compression in FCF == 0'''  # noqa: E501
    if (pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0) and (pkt.underlayer.getfieldval("fcf_panidcompress") == 0):  # noqa: E501
        return True
    else:
        return False


class Dot15d4CmdAssocReq(Packet):
    name = "802.15.4 Association Request Payload"
    fields_desc = [
        BitField("allocate_address", 0, 1),  # Allocate Address
        BitField("security_capability", 0, 1),  # Security Capability
        BitField("reserved2", 0, 1),  # bit 5 is reserved
        BitField("reserved1", 0, 1),  # bit 4 is reserved
        BitField("receiver_on_when_idle", 0, 1),  # Receiver On When Idle
        BitField("power_source", 0, 1),  # Power Source
        BitField("device_type", 0, 1),  # Device Type
        BitField("alternate_pan_coordinator", 0, 1),  # Alternate PAN Coordinator  # noqa: E501
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Association Request Payload ( Alt PAN Coord: %Dot15d4CmdAssocReq.alternate_pan_coordinator% Device Type: %Dot15d4CmdAssocReq.device_type% )")  # noqa: E501


class Dot15d4CmdAssocResp(Packet):
    name = "802.15.4 Association Response Payload"
    fields_desc = [
        XLEShortField("short_address", 0xFFFF),  # Address assigned to device from coordinator (0xFFFF == none)  # noqa: E501
        # Association Status
        # 0x00 == successful
        # 0x01 == PAN at capacity
        # 0x02 == PAN access denied
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
        ByteEnumField("association_status", 0x00, {0: 'successful', 1: 'PAN_at_capacity', 2: 'PAN_access_denied'}),  # noqa: E501
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Association Response Payload ( Association Status: %Dot15d4CmdAssocResp.association_status% Assigned Address: %Dot15d4CmdAssocResp.short_address% )")  # noqa: E501


class Dot15d4CmdDisassociation(Packet):
    name = "802.15.4 Disassociation Notification Payload"
    fields_desc = [
        # Disassociation Reason
        # 0x00 == Reserved
        # 0x01 == The coordinator wishes the device to leave the PAN
        # 0x02 == The device wishes to leave the PAN
        # 0x03 - 0x7f == Reserved
        # 0x80 - 0xff == Reserved for MAC primitive enumeration values
        ByteEnumField("disassociation_reason", 0x02, {1: 'coord_wishes_device_to_leave', 2: 'device_wishes_to_leave'}),  # noqa: E501
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Disassociation Notification Payload ( Disassociation Reason %Dot15d4CmdDisassociation.disassociation_reason% )")  # noqa: E501


class Dot15d4CmdGTSReq(Packet):
    name = "802.15.4 GTS request command"
    fields_desc = [
        # GTS Characteristics field (1 octet)
        # Reserved (bits 6-7)
        BitField("reserved", 0, 2),
        # Characteristics Type (bit 5)
        BitField("charact_type", 0, 1),
        # GTS Direction (bit 4)
        BitField("gts_dir", 0, 1),
        # GTS Length (bits 0-3)
        BitField("gts_len", 0, 4),
    ]

    def mysummary(self):
        return self.sprintf("802.15.4 GTS Request Command ( %Dot15d4CmdGTSReq.gts_len% : %Dot15d4CmdGTSReq.gts_dir% )")  # noqa: E501


# PAN ID conflict notification command frame is not necessary, only Dot15d4Cmd with cmd_id = 5 ("PANIDConflictNotify")  # noqa: E501
# Orphan notification command not necessary, only Dot15d4Cmd with cmd_id = 6 ("OrphanNotify")  # noqa: E501

# Bindings #
bind_layers(Dot15d4, Dot15d4Beacon, fcf_frametype=0)
bind_layers(Dot15d4, Dot15d4Data, fcf_frametype=1)
bind_layers(Dot15d4, Dot15d4Ack, fcf_frametype=2)
bind_layers(Dot15d4, Dot15d4Cmd, fcf_frametype=3)

# DLT Types #
conf.l2types.register(DLT_IEEE802_15_4_WITHFCS, Dot15d4FCS)
conf.l2types.register(DLT_IEEE802_15_4_NOFCS, Dot15d4)
