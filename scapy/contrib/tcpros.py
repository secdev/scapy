# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Víctor Mayoral-Vilches <v.mayoralv@gmail.com>

"""
TCPROS transport layer for ROS Melodic Morenia 1.14.5
"""

# scapy.contrib.description = TCPROS transport layer for ROS Melodic Morenia
# scapy.contrib.status = loads
# scapy.contrib.name = tcpros

import struct
from scapy.compat import raw
from scapy.fields import (
    LEIntField,
    StrLenField,
    FieldLenField,
    StrFixedLenField,
    ByteField,
)
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.packet import Packet, Raw, PacketListField
from scapy.config import conf


class TCPROS(Packet):
    """
    TCPROS is a transport layer for ROS Messages and Services. It uses standard
    TCP/IP sockets for transporting message data. Inbound connections are
    received via a TCP Server Socket with a header containing message data type
    and routing information.

    This class focuses on capturing the ROS Slave API

    An example package is presented below::

        B0 00 00 00 26 00 00 00 63 61 6C 6C 65 72 69 64  ....&...callerid
        3D 2F 72 6F 73 74 6F 70 69 63 5F 38 38 33 30 35  =/rostopic_88305
        5F 31 35 39 31 35 33 38 37 38 37 35 30 31 0A 00  _1591538787501..
        00 00 6C 61 74 63 68 69 6E 67 3D 31 27 00 00 00  ..latching=1'...
        6D 64 35 73 75 6D 3D 39 39 32 63 65 38 61 31 36  md5sum=992ce8a16
        38 37 63 65 63 38 63 38 62 64 38 38 33 65 63 37  87cec8c8bd883ec7
        33 63 61 34 31 64 31 1F 00 00 00 6D 65 73 73 61  3ca41d1....messa
        67 65 5F 64 65 66 69 6E 69 74 69 6F 6E 3D 73 74  ge_definition=st
        72 69 6E 67 20 64 61 74 61 0A 0E 00 00 00 74 6F  ring data.....to
        70 69 63 3D 2F 63 68 61 74 74 65 72 14 00 00 00  pic=/chatter....
        74 79 70 65 3D 73 74 64 5F 6D 73 67 73 2F 53 74  type=std_msgs/St
        72 69 6E 67                                      ring

    Sources:
        - http://wiki.ros.org/ROS/TCPROS
        - http://wiki.ros.org/ROS/Connection%20Header
        - https://docs.python.org/3/library/struct.html
        - https://scapy.readthedocs.io/en/latest/build_dissect.html

    TODO:
        - Extend to support subscriber's interactions
        - Unify with subscriber's header

    NOTES:
        - 4-byte length + [4-byte field length + field=value ]*
        - All length fields are little-endian integers. Field names and
            values are strings.
        - Cooked as of ROS Melodic Morenia v1.14.5.
    """

    name = "TCPROS"

    def guess_payload_class(self, payload):
        string_payload = payload.decode("iso-8859-1")  # decode to string
        # for search

        # flag indicating if the TCPROS encoding format is met
        #   4-byte length + [4-byte field length + field=value ]*
        total_length = len(payload)
        total_length_payload = struct.unpack("<I", payload[:4])[0]
        remain = payload[4:]
        remain_len = len(remain)
        # flag of the encoding format
        flag_encoding_format = (total_length > total_length_payload) and (
            total_length_payload == remain_len
        )

        if conf.debug_dissector:
            print(payload)
            print(string_payload)
            print("total_length: " + str(total_length))
            print("total_length_payload: " + str(total_length_payload))
            print("remain: " + str(remain))
            print(flag_encoding_format)

        flag_encoding_format_subfields = False
        if flag_encoding_format:
            # flag indicating that sub-fields meet
            # TCPROS encoding format:
            #  [4-byte field length + field=value ]*
            flag_encoding_format_subfields = True
            while remain:
                field_len_bytes = struct.unpack("<I", remain[:4])[0]
                current = remain[4:4 + field_len_bytes]
                remain = remain[4 + field_len_bytes:]

                if int(field_len_bytes) != len(current):
                    # print("BREAKING - int(field_len_bytes) != len(current)")
                    flag_encoding_format_subfields = False
                    break

        if (
            "callerid" in string_payload and
                flag_encoding_format and
                flag_encoding_format_subfields
        ):
            return TCPROSHeader
        elif flag_encoding_format and flag_encoding_format_subfields:
            return TCPROSBody
        elif flag_encoding_format:
            return TCPROSBodyVariation
        elif "HTTP/1.1" in string_payload and "text/xml" in string_payload:
            # NOTE:
            #   - "HTTP/1.1": corresponds with melodic
            #   - "HTTP/0.3": corresponds with kinetic

            # return HTTPROS  # corresponds with XML-RPC calls
            return HTTP  # use old-fashioned HTTP

        elif "HTTP/1.0" in string_payload and "text/xml" in string_payload:
            return HTTP  # use old-fashioned HTTP, which gives less control
        else:
            # return Packet.guess_payload_class(self, payload)
            return Raw(self, payload)  # returns Raw layer grouping not only
            # the payload but this layer itself.


class TCPROSElement(Packet):
    """
    Captures each one of the elements in the
    TCPROSHeader or TCPROSBody packages.

    NOTE: Used within other packages
    """

    name = "TCPROSElement"
    fields_desc = [
        # field
        FieldLenField(name="field_length",
                      default=None, length_of="field", fmt="<I"),
        StrLenField(name="field", length_from=lambda pkt: pkt.field_length,
                    default=""),
    ]

    def extract_padding(self, s):
        return "", s


class TCPROSHeader(Packet):
    """
    The Header of the TCPROS package::

        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |header.|  len1 |                    element1                   |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |               |  len2 |                                       |
        +-+-+-+-+-+-+-+-+-+-+-+-+                                       +
        |                            element2                           |
        +                       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       |  ...  |                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
        |                                                               |
        +                              ...                              +
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Generated with::
        protocol "header_length:4,len1:4,element1:32,len2:4,
            element2:64,...:4,...:80" --bits 32

    Typical header looks like::

        7C 00 00 00 12 00 00 00 63 61 6C 6C 65 72 69 64  |.......callerid
        3D 2F 6C 69 73 74 65 6E 65 72 27 00 00 00 6D 64  =/listener'...md
        35 73 75 6D 3D 39 39 32 63 65 38 61 31 36 38 37  5sum=992ce8a1687
        63 65 63 38 63 38 62 64 38 38 33 65 63 37 33 63  cec8c8bd883ec73c
        61 34 31 64 31 0D 00 00 00 74 63 70 5F 6E 6F 64  a41d1....tcp_nod
        65 6C 61 79 3D 30 0E 00 00 00 74 6F 70 69 63 3D  elay=0....topic=
        2F 63 68 61 74 74 65 72 14 00 00 00 74 79 70 65  /chatter....type
        3D 73 74 64 5F 6D 73 67 73 2F 53 74 72 69 6E 67  =std_msgs/String

    """

    name = "TCPROSHeader"
    __slots__ = Packet.__slots__ + ["nfields"]
    fields_desc = [
        # header_length
        FieldLenField(name="header_length",
                      default=None, length_of="list", fmt="<I"),
        # list  ## contains TCPROSElement
        PacketListField("list", None,
                        TCPROSElement, count_from=lambda pkt: pkt.nfields),
    ]

    def pre_dissect(self, s):
        """
        Called to prepare the layer before dissection
        """
        # To retrieve nfields, we need to go through the
        # whole header and dynamically count on the fields:
        self.nfields = 0
        total_header_length = struct.unpack("<I", raw(s)[:4])[0]
        if conf.debug_dissector:
            total_length = len(s)
            print("total_length: " + str(total_length))
            print("total_header_length: " + str(total_header_length))
        remain = raw(s)[4:total_header_length]
        while remain:
            field_len_bytes = struct.unpack("<I", remain[:4])[0]
            remain = remain[4 + field_len_bytes:]
            if conf.debug_dissector:
                print("field_len_bytes: " + str(field_len_bytes))
                current = remain[:4 + field_len_bytes]
                print("current: " + str(current))
                print("remain: " + str(remain))
            self.nfields += 1
        return s

    def do_dissect_payload(self, s):
        self.guess_payload_class(s)

    def extract_padding(self, s):
        return "", s


class TCPROSBody(Packet):
    """
    TCPROS body type of package::

        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |body_l.|  len1 |                    element1                   |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |               |  len2 |                                       |
        +-+-+-+-+-+-+-+-+-+-+-+-+                                       +
        |                            element2                           |
        +                       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       |  ...  |                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
        |                                                               |
        +                              ...                              +
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Generated with::
        protocol "body_length:4,len1:4,element1:32,len2:4,
            element2:64,...:4,...:80" --bits 32

    As per ROS Melodic Morenia v1.14.5. this package is generally
    seen separated from a TCPROSHeader. A simple such package::

        12 00 00 00 0E 00 00 00 68 65 6C 6C 6F 20 77 6F  ........hello wo
        72 6C 64 20 31 36                                rld 16

    """

    name = "TCPROSBody"
    __slots__ = Packet.__slots__ + ["nfields_body"]
    fields_desc = [
        FieldLenField(name="body_length",
                      default=None, length_of="list", fmt="<I"),
        # header
        PacketListField(
            "list", None, TCPROSElement,
            count_from=lambda pkt: pkt.nfields_body
        ),
    ]

    def pre_dissect(self, s):
        """
        Called to prepare the layer before dissection
        """
        # To retrieve nfields_body, we need to go through the
        # whole header and dynamically count on the fields:
        self.nfields_body = 0
        total_header_length = struct.unpack("<I", raw(s)[:4])[0]
        remain = raw(s)[4:total_header_length]
        if conf.debug_dissector:
            total_length = len(s)
            print("total_length: " + str(total_length))
            print("total_header_length: " + str(total_header_length))
        while remain:
            field_len_bytes = struct.unpack("<I", remain[:4])[0]
            remain = remain[4 + field_len_bytes:]
            if conf.debug_dissector:
                print("field_len_bytes: " + str(field_len_bytes))
                current = remain[:4 + field_len_bytes]
                print("current: " + str(current))
                print("remain: " + str(remain))
            self.nfields_body += 1
        return s

    def do_dissect_payload(self, s):
        self.guess_payload_class(s)

    def extract_padding(self, s):
        return "", s


class TCPROSBodyVariation(TCPROSBody):
    """
    TCPROS body variation type of package::

        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |body_l.|sequen.|        signature        |  len1 |             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                     element1                    |  ...  |     |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     +
        |                                                               |
        +                              ...                              +
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Generated with::
        protocol "body_length:4,sequence:4,signature:13,len1:4,
            element1:32,...:4,...:67" --bits 32

    As per ROS Melodic Morenia v1.14.5. this package is generally
    seen separated from a TCPROSHeader. An exemplary such package::

        AB 00 00 00 00 00 00 00 7D 81 03 5F 7C A4 3F 0E  ........}.._|.?.
        00 00 00 00 02 09 00 00 00 2F 6C 69 73 74 65 6E  ........./listen
        65 72 18 00 00 00 49 20 68 65 61 72 64 3A 20 5B  er....I heard: [
        68 65 6C 6C 6F 20 77 6F 72 6C 64 20 33 5D 47 00  hello world 3]G.
        00 00 2F 74 6D 70 2F 62 69 6E 61 72 79 64 65 62  ../tmp/binarydeb
        2F 72 6F 73 2D 6D 65 6C 6F 64 69 63 2D 72 6F 73  /ros-melodic-ros
        63 70 70 2D 74 75 74 6F 72 69 61 6C 73 2D 30 2E  cpp-tutorials-0.
        39 2E 32 2F 6C 69 73 74 65 6E 65 72 2F 6C 69 73  9.2/listener/lis
        74 65 6E 65 72 2E 63 70 70 0F 00 00 00 63 68 61  tener.cpp....cha
        74 74 65 72 43 61 6C 6C 62 61 63 6B 26 00 00 00  tterCallback&...
        01 00 00 00 07 00 00 00 2F 72 6F 73 6F 75 74     ......../rosout

    and the next one referring also to '/listener'::

        AB 00 00 00 01 00 00 00 7D 81 03 5F 00 54 42 14  ........}.._.TB.
        00 00 00 00 02 09 00 00 00 2F 6C 69 73 74 65 6E  ........./listen
        65 72 18 00 00 00 49 20 68 65 61 72 64 3A 20 5B  er....I heard: [
        68 65 6C 6C 6F 20 77 6F 72 6C 64 20 34 5D 47 00  hello world 4]G.
        00 00 2F 74 6D 70 2F 62 69 6E 61 72 79 64 65 62  ../tmp/binarydeb
        2F 72 6F 73 2D 6D 65 6C 6F 64 69 63 2D 72 6F 73  /ros-melodic-ros
        63 70 70 2D 74 75 74 6F 72 69 61 6C 73 2D 30 2E  cpp-tutorials-0.
        39 2E 32 2F 6C 69 73 74 65 6E 65 72 2F 6C 69 73  9.2/listener/lis
        74 65 6E 65 72 2E 63 70 70 0F 00 00 00 63 68 61  tener.cpp....cha
        74 74 65 72 43 61 6C 6C 62 61 63 6B 26 00 00 00  tterCallback&...
        01 00 00 00 07 00 00 00 2F 72 6F 73 6F 75 74     ......../rosout

    NOTE: not all packages are disgested appropriately and some
    fields need to be better understood (e.g. signature) for
    appropriate building.

    NOTE 2: Needs further research to convert Padding at the end to
    something that makes sense.

    """

    name = "TCPROSBodyVariation"
    fields_desc = [
        # body_length
        FieldLenField(name="body_length",
                      default=None, length_of="list", fmt="<I"),
        # sequence
        LEIntField(name="sequence", default=0),
        # signature  ## not documented, guessing
        StrFixedLenField("signature", None, length=13),
        # list
        PacketListField(
            "list", None, TCPROSElement,
            count_from=lambda pkt: pkt.nfields_body
        ),
    ]


class XMLRPC(Packet):
    """
    XML-RPC is a remote procedure call (RPC) protocol which uses XML to encode
    its calls and HTTP as a transport mechanism.

    ROS uses XML-RPC for a variety of interactions including:
        - Register/unregister subscribers and publishers
        - Set or get parameters
        - Updates in the ROS computational graph, across endpoints
        - Request of transports, between endpoints

    This class aims to abstract all these interactions while building on top
    of the Master and Parameter APIs of ROS (the Slave API is abstracted in
    the ROSTCP class).

    An example package of a publisher initiating communication is presented
    below wherein this particular package requests the Master's PID
    (HTTP Request)::

        0000  02 42 0C 00 00 02 02 42 0C 00 00 04 08 00 45 00  .B.....B......E.
        0010  01 7C 4F F8 40 00 40 06 D1 7E 0C 00 00 04 0C 00  .|O.@.@..~......
        0020  00 02 8E 62 2C 2F C7 A9 92 A9 87 00 82 4C 80 18  ...b,/.......L..
        0030  01 FD 19 74 00 00 01 01 08 0A BB 36 D2 1A 39 82  ...t.......6..9.
        0040  4B 7A 50 4F 53 54 20 2F 52 50 43 32 20 48 54 54  KzPOST /RPC2 HTT
        0050  50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 31 32 2E  P/1.1..Host: 12.
        0060  30 2E 30 2E 32 3A 31 31 33 31 31 0D 0A 41 63 63  0.0.2:11311..Acc
        0070  65 70 74 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A  ept-Encoding: gz
        0080  69 70 0D 0A 55 73 65 72 2D 41 67 65 6E 74 3A 20  ip..User-Agent:
        0090  78 6D 6C 72 70 63 6C 69 62 2E 70 79 2F 31 2E 30  xmlrpclib.py/1.0
        00a0  2E 31 20 28 62 79 20 77 77 77 2E 70 79 74 68 6F  .1 (by www.pytho
        00b0  6E 77 61 72 65 2E 63 6F 6D 29 0D 0A 43 6F 6E 74  nware.com)..Cont
        00c0  65 6E 74 2D 54 79 70 65 3A 20 74 65 78 74 2F 78  ent-Type: text/x
        00d0  6D 6C 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67  ml..Content-Leng
        00e0  74 68 3A 20 31 35 39 0D 0A 0D 0A 3C 3F 78 6D 6C  th: 159....<?xml
        00f0  20 76 65 72 73 69 6F 6E 3D 27 31 2E 30 27 3F 3E   version='1.0'?>
        0100  0A 3C 6D 65 74 68 6F 64 43 61 6C 6C 3E 0A 3C 6D  .<methodCall>.<m
        0110  65 74 68 6F 64 4E 61 6D 65 3E 67 65 74 50 69 64  ethodName>getPid
        0120  3C 2F 6D 65 74 68 6F 64 4E 61 6D 65 3E 0A 3C 70  </methodName>.<p
        0130  61 72 61 6D 73 3E 0A 3C 70 61 72 61 6D 3E 0A 3C  arams>.<param>.<
        0140  76 61 6C 75 65 3E 3C 73 74 72 69 6E 67 3E 2F 72  value><string>/r
        0150  6F 73 74 6F 70 69 63 3C 2F 73 74 72 69 6E 67 3E  ostopic</string>
        0160  3C 2F 76 61 6C 75 65 3E 0A 3C 2F 70 61 72 61 6D  </value>.</param
        0170  3E 0A 3C 2F 70 61 72 61 6D 73 3E 0A 3C 2F 6D 65  >.</params>.</me
        0180  74 68 6F 64 43 61 6C 6C 3E 0A                    thodCall>.

    The counterpart (the Master) answers with (HTTP Response)::

        0000  02 42 0C 00 00 04 02 42 0C 00 00 02 08 00 45 00  .B.....B......E.
        0010  01 A2 8C CD 40 00 40 06 94 83 0C 00 00 02 0C 00  ....@.@.........
        0020  00 04 2C 2F 8E 62 87 00 82 4C C7 A9 93 F1 80 18  ..,/.b...L......
        0030  01 F6 19 9A 00 00 01 01 08 0A 39 82 4B 7B BB 36  ..........9.K{.6
        0040  D2 1A 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F  ..HTTP/1.1 200 O
        0050  4B 0D 0A 53 65 72 76 65 72 3A 20 42 61 73 65 48  K..Server: BaseH
        0060  54 54 50 2F 30 2E 33 20 50 79 74 68 6F 6E 2F 32  TTP/0.3 Python/2
        0070  2E 37 2E 31 37 0D 0A 44 61 74 65 3A 20 53 75 6E  .7.17..Date: Sun
        0080  2C 20 30 36 20 44 65 63 20 32 30 32 30 20 31 35  , 06 Dec 2020 15
        0090  3A 31 37 3A 33 38 20 47 4D 54 0D 0A 43 6F 6E 74  :17:38 GMT..Cont
        00a0  65 6E 74 2D 74 79 70 65 3A 20 74 65 78 74 2F 78  ent-type: text/x
        00b0  6D 6C 0D 0A 43 6F 6E 74 65 6E 74 2D 6C 65 6E 67  ml..Content-leng
        00c0  74 68 3A 20 32 32 39 0D 0A 0D 0A 3C 3F 78 6D 6C  th: 229....<?xml
        00d0  20 76 65 72 73 69 6F 6E 3D 27 31 2E 30 27 3F 3E   version='1.0'?>
        00e0  0A 3C 6D 65 74 68 6F 64 52 65 73 70 6F 6E 73 65  .<methodResponse
        00f0  3E 0A 3C 70 61 72 61 6D 73 3E 0A 3C 70 61 72 61  >.<params>.<para
        0100  6D 3E 0A 3C 76 61 6C 75 65 3E 3C 61 72 72 61 79  m>.<value><array
        0110  3E 3C 64 61 74 61 3E 0A 3C 76 61 6C 75 65 3E 3C  ><data>.<value><
        0120  69 6E 74 3E 31 3C 2F 69 6E 74 3E 3C 2F 76 61 6C  int>1</int></val
        0130  75 65 3E 0A 3C 76 61 6C 75 65 3E 3C 73 74 72 69  ue>.<value><stri
        0140  6E 67 3E 3C 2F 73 74 72 69 6E 67 3E 3C 2F 76 61  ng></string></va
        0150  6C 75 65 3E 0A 3C 76 61 6C 75 65 3E 3C 69 6E 74  lue>.<value><int
        0160  3E 33 39 38 3C 2F 69 6E 74 3E 3C 2F 76 61 6C 75  >398</int></value
        0170  65 3E 0A 3C 2F 64 61 74 61 3E 3C 2F 61 72 72 61  e>.</data></arra
        0180  79 3E 3C 2F 76 61 6C 75 65 3E 0A 3C 2F 70 61 72  y></value>.</par
        0190  61 6D 3E 0A 3C 2F 70 61 72 61 6D 73 3E 0A 3C 2F  am>.</params>.</
        01a0  6D 65 74 68 6F 64 52 65 73 70 6F 6E 73 65 3E 0A  methodResponse>.


    In another communication, and endpoint could request a parameter using the
    Parameter Server API (HTTP Request)::

        0000  02 42 0C 00 00 02 02 42 0C 00 00 04 08 00 45 00  .B.....B......E.
        0010  01 C0 8B 72 40 00 40 06 95 C0 0C 00 00 04 0C 00  ...r@.@.........
        0020  00 02 90 10 2C 2F 9D 09 47 7F EC C3 08 BD 80 18  ....,/..G.......
        0030  01 FD 19 B8 00 00 01 01 08 0A BB 86 68 91 39 D1  ............h.9.
        0040  E1 F1 50 4F 53 54 20 2F 52 50 43 32 20 48 54 54  ..POST /RPC2 HTT
        0050  50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 31 32 2E  P/1.1..Host: 12.
        0060  30 2E 30 2E 32 3A 31 31 33 31 31 0D 0A 41 63 63  0.0.2:11311..Acc
        0070  65 70 74 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A  ept-Encoding: gz
        0080  69 70 0D 0A 55 73 65 72 2D 41 67 65 6E 74 3A 20  ip..User-Agent:
        0090  78 6D 6C 72 70 63 6C 69 62 2E 70 79 2F 31 2E 30  xmlrpclib.py/1.0
        00a0  2E 31 20 28 62 79 20 77 77 77 2E 70 79 74 68 6F  .1 (by www.pytho
        00b0  6E 77 61 72 65 2E 63 6F 6D 29 0D 0A 43 6F 6E 74  nware.com)..Cont
        00c0  65 6E 74 2D 54 79 70 65 3A 20 74 65 78 74 2F 78  ent-Type: text/x
        00d0  6D 6C 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67  ml..Content-Leng
        00e0  74 68 3A 20 32 32 37 0D 0A 0D 0A 3C 3F 78 6D 6C  th: 227....<?xml
        00f0  20 76 65 72 73 69 6F 6E 3D 27 31 2E 30 27 3F 3E   version='1.0'?>
        0100  0A 3C 6D 65 74 68 6F 64 43 61 6C 6C 3E 0A 3C 6D  .<methodCall>.<m
        0110  65 74 68 6F 64 4E 61 6D 65 3E 67 65 74 50 61 72  ethodName>getPar
        0120  61 6D 3C 2F 6D 65 74 68 6F 64 4E 61 6D 65 3E 0A  am</methodName>.
        0130  3C 70 61 72 61 6D 73 3E 0A 3C 70 61 72 61 6D 3E  <params>.<param>
        0140  0A 3C 76 61 6C 75 65 3E 3C 73 74 72 69 6E 67 3E  .<value><string>
        0150  2F 72 6F 73 70 61 72 61 6D 2D 38 32 30 34 33 3C  /rosparam-82043<
        0160  2F 73 74 72 69 6E 67 3E 3C 2F 76 61 6C 75 65 3E  /string></value>
        0170  0A 3C 2F 70 61 72 61 6D 3E 0A 3C 70 61 72 61 6D  .</param>.<param
        0180  3E 0A 3C 76 61 6C 75 65 3E 3C 73 74 72 69 6E 67  >.<value><string
        0190  3E 2F 72 6F 73 64 69 73 74 72 6F 3C 2F 73 74 72  >/rosdistro</str
        01a0  69 6E 67 3E 3C 2F 76 61 6C 75 65 3E 0A 3C 2F 70  ing></value>.</p
        01b0  61 72 61 6D 3E 0A 3C 2F 70 61 72 61 6D 73 3E 0A  aram>.</params>.
        01c0  3C 2F 6D 65 74 68 6F 64 43 61 6C 6C 3E 0A        </methodCall>.

    Sources:
        - https://aliasrobotics.com/files/
                securing_robot_endpoints_ot_environment.pdf
        - http://wiki.ros.org/ROS/Master_API
        - http://wiki.ros.org/ROS/Slave_API
        - http://wiki.ros.org/ROS/Parameter%20Server%20API

    """

    name = "XMLRPC"

    def guess_payload_class(self, payload):
        string_payload = payload.decode("iso-8859-1")  # decode for search
        # total_length = len(payload)

        if "xml" in string_payload and "version='1.0'" in string_payload:
            if isinstance(self.underlayer, HTTPRequest):
                return XMLRPCCall
            elif isinstance(self.underlayer, HTTPResponse):
                return XMLRPCResponse
            else:
                print("failed to match")
                return Raw
        else:
            return Raw(self, payload)  # returns Raw layer grouping not only
            # the payload but this layer itself.


# Fields
class XMLRPCSeparator(ByteField):
    """
    Separator of XML-RPC components - 0x0a

    """

    def __init__(self, name, default="0x0a"):
        ByteField.__init__(self, name, default)


# Packages
class XMLRPCCall(Packet):
    """
    Request side of the ROS XMLPC elements used by Master and Parameter APIs
    Exemplary package::

        0000  02 42 0C 00 00 02 02 42 0C 00 00 04 08 00 45 00  .B.....B......E.
        0010  01 C0 8B 72 40 00 40 06 95 C0 0C 00 00 04 0C 00  ...r@.@.........
        0020  00 02 90 10 2C 2F 9D 09 47 7F EC C3 08 BD 80 18  ....,/..G.......
        0030  01 FD 19 B8 00 00 01 01 08 0A BB 86 68 91 39 D1  ............h.9.
        0040  E1 F1 50 4F 53 54 20 2F 52 50 43 32 20 48 54 54  ..POST /RPC2 HTT
        0050  50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 31 32 2E  P/1.1..Host: 12.
        0060  30 2E 30 2E 32 3A 31 31 33 31 31 0D 0A 41 63 63  0.0.2:11311..Acc
        0070  65 70 74 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A  ept-Encoding: gz
        0080  69 70 0D 0A 55 73 65 72 2D 41 67 65 6E 74 3A 20  ip..User-Agent:
        0090  78 6D 6C 72 70 63 6C 69 62 2E 70 79 2F 31 2E 30  xmlrpclib.py/1.0
        00a0  2E 31 20 28 62 79 20 77 77 77 2E 70 79 74 68 6F  .1 (by www.pytho
        00b0  6E 77 61 72 65 2E 63 6F 6D 29 0D 0A 43 6F 6E 74  nware.com)..Cont
        00c0  65 6E 74 2D 54 79 70 65 3A 20 74 65 78 74 2F 78  ent-Type: text/x
        00d0  6D 6C 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67  ml..Content-Leng
        00e0  74 68 3A 20 32 32 37 0D 0A 0D 0A 3C 3F 78 6D 6C  th: 227....<?xml
        00f0  20 76 65 72 73 69 6F 6E 3D 27 31 2E 30 27 3F 3E   version='1.0'?>
        0100  0A 3C 6D 65 74 68 6F 64 43 61 6C 6C 3E 0A 3C 6D  .<methodCall>.<m
        0110  65 74 68 6F 64 4E 61 6D 65 3E 67 65 74 50 61 72  ethodName>getPar
        0120  61 6D 3C 2F 6D 65 74 68 6F 64 4E 61 6D 65 3E 0A  am</methodName>.
        0130  3C 70 61 72 61 6D 73 3E 0A 3C 70 61 72 61 6D 3E  <params>.<param>
        0140  0A 3C 76 61 6C 75 65 3E 3C 73 74 72 69 6E 67 3E  .<value><string>
        0150  2F 72 6F 73 70 61 72 61 6D 2D 38 32 30 34 33 3C  /rosparam-82043<
        0160  2F 73 74 72 69 6E 67 3E 3C 2F 76 61 6C 75 65 3E  /string></value>
        0170  0A 3C 2F 70 61 72 61 6D 3E 0A 3C 70 61 72 61 6D  .</param>.<param
        0180  3E 0A 3C 76 61 6C 75 65 3E 3C 73 74 72 69 6E 67  >.<value><string
        0190  3E 2F 72 6F 73 64 69 73 74 72 6F 3C 2F 73 74 72  >/rosdistro</str
        01a0  69 6E 67 3E 3C 2F 76 61 6C 75 65 3E 0A 3C 2F 70  ing></value>.</p
        01b0  61 72 61 6D 3E 0A 3C 2F 70 61 72 61 6D 73 3E 0A  aram>.</params>.
        01c0  3C 2F 6D 65 74 68 6F 64 43 61 6C 6C 3E 0A        </methodCall>.

    """

    name = "XMLRPCCall"
    __slots__ = Packet.__slots__ + ["methodname_size", "params_size"]
    fields_desc = [
        # <?xml version='1.0'?>.<methodCall>.
        StrFixedLenField(
            "version",
            "<?xml version='1.0'?>\n",
            length=22,  # 22
        ),
        # XMLRPCSeparator("separator_version"),
        StrFixedLenField("methodcall_opentag", "<methodCall>\n", length=13),
        # <methodName>getParam</methodName>.
        StrFixedLenField("methodname_opentag", "<methodName>", length=12),
        StrLenField("methodname", "getParam",
                    length_from=lambda pkt: pkt.methodname_size),
        StrFixedLenField("methodname_closetag", "</methodName>\n", length=14),
        # <params>.
        StrFixedLenField("params_opentag", "<params>\n", length=9),
        # [<param>.<value><string>/rosparam-82043</string></value>.</param>.]
        StrLenField(
            "params",
            "<param>\n<value><string>/rosparam-82043" + \
            "</string></value>\n</param>\n",
            length_from=lambda pkt: pkt.params_size,
        ),
        # </params>.</methodCall>.
        StrFixedLenField("params_closetag", "</params>\n", length=10),
        StrFixedLenField("methodcall_closetag", "</methodCall>\n", length=14),
    ]

    def pre_dissect(self, s):
        """
        Calculate the sizes of:
            - methodname
            - params

        See https://docs.python.org/3/library/struct.html
            for the unpack (e.g. "<I") options
        """
        decoded_s = s.decode("iso-8859-1")  # from bytes, to string

        self.methodname_size = len(
            decoded_s[
                decoded_s.find("<methodName>") +
                len("<methodName>"):decoded_s.find("</methodName>")
            ]
        )

        self.params_size = len(
            decoded_s[
                decoded_s.find("<params>\n") +
                len("<params>\n"):decoded_s.find("</params>")
            ]
        )

        if conf.debug_dissector:
            print(self.methodname_size)
            print(self.params_size)
        return s

    def do_dissect_payload(self, s):
        self.guess_payload_class(s)


class XMLRPCResponse(Packet):
    """
    Response side of the ROS XMLPC elements used by Master and Parameter APIs
    Exemplary package::

        0000  02 42 0C 00 00 04 02 42 0C 00 00 02 08 00 45 00  .B.....B......E.
        0010  01 A2 8C CD 40 00 40 06 94 83 0C 00 00 02 0C 00  ....@.@.........
        0020  00 04 2C 2F 8E 62 87 00 82 4C C7 A9 93 F1 80 18  ..,/.b...L......
        0030  01 F6 19 9A 00 00 01 01 08 0A 39 82 4B 7B BB 36  ..........9.K{.6
        0040  D2 1A 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F  ..HTTP/1.1 200 O
        0050  4B 0D 0A 53 65 72 76 65 72 3A 20 42 61 73 65 48  K..Server: BaseH
        0060  54 54 50 2F 30 2E 33 20 50 79 74 68 6F 6E 2F 32  TTP/0.3 Python/2
        0070  2E 37 2E 31 37 0D 0A 44 61 74 65 3A 20 53 75 6E  .7.17..Date: Sun
        0080  2C 20 30 36 20 44 65 63 20 32 30 32 30 20 31 35  , 06 Dec 2020 15
        0090  3A 31 37 3A 33 38 20 47 4D 54 0D 0A 43 6F 6E 74  :17:38 GMT..Cont
        00a0  65 6E 74 2D 74 79 70 65 3A 20 74 65 78 74 2F 78  ent-type: text/x
        00b0  6D 6C 0D 0A 43 6F 6E 74 65 6E 74 2D 6C 65 6E 67  ml..Content-leng
        00c0  74 68 3A 20 32 32 39 0D 0A 0D 0A 3C 3F 78 6D 6C  th: 229....<?xml
        00d0  20 76 65 72 73 69 6F 6E 3D 27 31 2E 30 27 3F 3E   version='1.0'?>
        00e0  0A 3C 6D 65 74 68 6F 64 52 65 73 70 6F 6E 73 65  .<methodResponse
        00f0  3E 0A 3C 70 61 72 61 6D 73 3E 0A 3C 70 61 72 61  >.<params>.<para
        0100  6D 3E 0A 3C 76 61 6C 75 65 3E 3C 61 72 72 61 79  m>.<value><array
        0110  3E 3C 64 61 74 61 3E 0A 3C 76 61 6C 75 65 3E 3C  ><data>.<value><
        0120  69 6E 74 3E 31 3C 2F 69 6E 74 3E 3C 2F 76 61 6C  int>1</int></val
        0130  75 65 3E 0A 3C 76 61 6C 75 65 3E 3C 73 74 72 69  ue>.<value><stri
        0140  6E 67 3E 3C 2F 73 74 72 69 6E 67 3E 3C 2F 76 61  ng></string></va
        0150  6C 75 65 3E 0A 3C 76 61 6C 75 65 3E 3C 69 6E 74  lue>.<value><int
        0160  3E 33 39 38 3C 2F 69 6E 74 3E 3C 2F 76 61 6C 75  >398</int></value
        0170  65 3E 0A 3C 2F 64 61 74 61 3E 3C 2F 61 72 72 61  e>.</data></arra
        0180  79 3E 3C 2F 76 61 6C 75 65 3E 0A 3C 2F 70 61 72  y></value>.</par
        0190  61 6D 3E 0A 3C 2F 70 61 72 61 6D 73 3E 0A 3C 2F  am>.</params>.</
        01a0  6D 65 74 68 6F 64 52 65 73 70 6F 6E 73 65 3E 0A  methodResponse>.
    """

    name = "XMLRPCResponse"
    __slots__ = Packet.__slots__ + ["params_size"]
    fields_desc = [
        # <?xml version='1.0'?>\n
        StrFixedLenField("version", "<?xml version='1.0'?>\n", length=22),
        # XMLRPCSeparator("separator_version"),
        # <methodResponse>\n
        StrFixedLenField("methodcall_opentag", "<methodResponse>\n",
                         length=17),
        # <params>\n
        StrFixedLenField("params_opentag", "<params>\n",
                         length=9),
        # <param>\n<value><array><data>\n
        #   <value><int>1</int></value>\n
        #   <value><string>Parameter [/rosdistro]</string></value>\n
        #   <value><string>melodic\n</string></value>\n
        #   </data></array></value>\n</param>\n
        StrLenField("params", "", length_from=lambda pkt: pkt.params_size),
        # </params>\n</methodResponse>\n
        StrFixedLenField("params_closetag", "</params>\n", length=10),
        StrFixedLenField("methodcall_closetag", "</methodResponse>\n",
                         length=18),
    ]

    def pre_dissect(self, s):
        """
        Calculate the sizes of:
            - methodname
            - params

        See https://docs.python.org/3/library/struct.html
            for the unpack (e.g. "<I") options
        """
        decoded_s = s.decode("iso-8859-1")  # from bytes, to string

        self.params_size = len(
            decoded_s[
                decoded_s.find("<params>\n") +
                len("<params>\n"):decoded_s.find("</params>")
            ]
        )

        if conf.debug_dissector:
            print(self.params_size)
        return s

    def do_dissect_payload(self, s):
        self.guess_payload_class(s)
