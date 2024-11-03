# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2024 Lucas Drufva <lucas.drufva@gmail.com>

# scapy.contrib.description = WebSocket
# scapy.contrib.status = loads

# Based on rfc6455

import struct
import base64
import zlib
from hashlib import sha1
from scapy.fields import (BitFieldLenField, Field, BitField, BitEnumField, ConditionalField, XNBytesField)
from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP
from scapy.layers.inet import TCP
from scapy.packet import Packet
from scapy.error import Scapy_Exception
import logging


class PayloadLenField(BitFieldLenField):

    def __init__(self, name, default, length_of, size=0, tot_size=0, end_tot_size=0):
        # Initialize with length_of (like in BitFieldLenField) and lengthFrom (like in BitLenField)
        super().__init__(name, default, size, length_of=length_of, tot_size=tot_size, end_tot_size=end_tot_size)

    def getfield(self, pkt, s):
        s, _ = s
        # Get the 7-bit field (first byte)
        length_byte = s[0] & 0x7F
        s = s[1:]

        if length_byte <= 125:
            # 7-bit length
            return s, length_byte
        elif length_byte == 126:
            # 16-bit length
            length = struct.unpack("!H", s[:2])[0]  # Read 2 bytes
            s = s[2:]
            return s, length
        elif length_byte == 127:
            # 64-bit length
            length = struct.unpack("!Q", s[:8])[0]  # Read 8 bytes
            s = s[8:]
            return s, length

    def addfield(self, pkt, s, val):
        p_field, p_val = pkt.getfield_and_val(self.length_of)
        val = p_field.i2len(pkt, p_val)

        if val <= 125:
            self.size = 7
            return super().addfield(pkt, s, val)
        elif val <= 0xFFFF:
            self.size = 7+16
            s, _, masked = s
            return s + struct.pack("!BH", 126 | masked, val)
        elif val <= 0xFFFFFFFFFFFFFFFF:
            self.size = 7+64
            s, _, masked = s
            return s + struct.pack("!BQ", 127 | masked, val)
        else:
            raise Scapy_Exception("%s: Payload length too large" %
                                    self.__class__.__name__)



class PayloadField(Field):
    """
    Field for handling raw byte payloads with dynamic size.
    The length of the payload is described by a preceding PayloadLenField.
    """
    __slots__ = ["lengthFrom"]
    
    def __init__(self, name, lengthFrom):
        """
        :param name: Field name
        :param lengthFrom: Field name that provides the length of the payload
        """
        super(PayloadField, self).__init__(name, None)
        self.lengthFrom = lengthFrom

    def getfield(self, pkt, s):
        # Fetch the length from the field that specifies the length
        length = getattr(pkt, self.lengthFrom)
        payloadData = s[:length]

        if pkt.mask:
            key = struct.pack("I", pkt.maskingKey)[::-1]
            data_int = int.from_bytes(payloadData, 'big')
            mask_repeated = key * (len(payloadData) // 4) + key[: len(payloadData) % 4]
            mask_int = int.from_bytes(mask_repeated, 'big')
            payloadData = (data_int ^ mask_int).to_bytes(len(payloadData), 'big')

        if("permessage-deflate" in pkt.extensions):
            try:
                payloadData = pkt.decoder[0](payloadData + b"\x00\x00\xff\xff")
            except Exception: 
                logging.debug("Failed to decompress payload", payloadData)

        return s[length:], payloadData

    def addfield(self, pkt, s, val):
        if pkt.mask:
            key = struct.pack("I", pkt.maskingKey)[::-1]
            data_int = int.from_bytes(val, 'big')
            mask_repeated = key * (len(val) // 4) + key[: len(val) % 4]
            mask_int = int.from_bytes(mask_repeated, 'big')
            val = (data_int ^ mask_int).to_bytes(len(val), 'big')

        return s + bytes(val)

    def i2len(self, pkt, val):
        # Length of the payload in bytes
        return len(val)

class WebSocket(Packet):
    __slots__ = ["extensions", "decoder"]

    name = "WebSocket"
    fields_desc = [
        BitField("fin", 0, 1),
        BitField("rsv", 0, 3),
        BitEnumField("opcode", 0, 4, 
            {
                0x0: "none",
                0x1: "text",
                0x2: "binary",
                0x8: "close",
                0x9: "ping",
                0xA: "pong",
            }),
        BitField("mask", 0, 1),
        PayloadLenField("payloadLen", 0, length_of="wsPayload", size=1),
        ConditionalField(XNBytesField("maskingKey", 0, sz=4), lambda pkt: pkt.mask == 1),
        PayloadField("wsPayload", lengthFrom="payloadLen")
    ]

    def __init__(self, pkt=None, extensions=[], decoder=None, *args, **fields):
        self.extensions = extensions
        self.decoder = decoder
        super().__init__(_pkt=pkt, *args, **fields)

    def extract_padding(self, s):
        return '', s

    @classmethod
    def tcp_reassemble(cls, data, metadata, session):
        # data = the reassembled data from the same request/flow
        # metadata = empty dictionary, that can be used to store data
        #            during TCP reassembly
        # session = a dictionary proper to the bidirectional TCP session,
        #           that can be used to store anything
        # [...]
        # If the packet is available, return it. Otherwise don't.
        # Whenever you return a packet, the buffer will be discarded.


        HANDSHAKE_STATE_CLIENT_OPEN = 0
        HANDSHAKE_STATE_SERVER_OPEN = 1
        HANDSHAKE_STATE_OPEN = 2

        if "handshake-state" not in session:
            session["handshake-state"] = HANDSHAKE_STATE_CLIENT_OPEN

        if "extensions" not in session:
            session["extensions"] = {}


        if session["handshake-state"] == HANDSHAKE_STATE_CLIENT_OPEN:
            http_data = HTTP(data)
            if HTTPRequest in http_data:
                http_data = http_data[HTTPRequest]
            else:
                return http_data

            if http_data.Method != b"GET":
                return HTTP()/http_data

            if not http_data.Upgrade or http_data.Upgrade.lower() != b"websocket":
                return HTTP()/http_data
            
            if not http_data.Unknown_Headers or b"Sec-WebSocket-Key" not in http_data.Unknown_Headers:
                return HTTP()/http_data
            
            session["handshake-key"] = http_data.Unknown_Headers[b"Sec-WebSocket-Key"]

            if "original" in metadata:
                session["server-port"] = metadata["original"][TCP].dport

            session["handshake-state"] = HANDSHAKE_STATE_SERVER_OPEN
            
            return http_data

        elif session["handshake-state"] == HANDSHAKE_STATE_SERVER_OPEN:
            http_data = HTTP(data)
            if HTTPResponse in http_data:
                http_data = http_data[HTTPResponse]
            else:
                return http_data

            if not http_data.Upgrade.lower() == b"websocket":
                return HTTP()/http_data
            
            # Verify key-accept handshake:
            correct_accept = base64.b64encode(sha1(session["handshake-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11".encode()).digest())
            if not http_data.Unknown_Headers or b"Sec-WebSocket-Accept" not in http_data.Unknown_Headers or http_data.Unknown_Headers[b"Sec-WebSocket-Accept"] != correct_accept:
                # TODO: handle or Logg wrong accept key
                pass

            if b"Sec-WebSocket-Extensions" in http_data.Unknown_Headers:
                session["extensions"] = {}
                for extension in http_data.Unknown_Headers[b"Sec-WebSocket-Extensions"].decode().strip().split(";"):
                    key_value_pair = extension.split("=", 1) + [None]
                    session["extensions"][key_value_pair[0].strip()] = key_value_pair[1]          

                if "permessage-deflate" in session["extensions"]:
                    def create_decompressor(window_bits):
                        decoder = zlib.decompressobj(wbits=-window_bits)
                        def decomp(data):
                            nonlocal decoder
                            return decoder.decompress(data, 0)
                        
                        def reset():
                            nonlocal decoder
                            nonlocal window_bits
                            decoder = zlib.decompressobj(wbits=-window_bits)
                        
                        return (decomp, reset)
                    
                    # Default values
                    client_wb = 12
                    server_wb = 15

                    # Check for new values in extensions header
                    if "client_max_window_bits" in session["extensions"]:
                        client_wb = int(session["extensions"]["client_max_window_bits"])
                    
                    if "server_max_window_bits" in session["extensions"]:
                        server_wb = int(session["extensions"]["server_max_window_bits"])
                        

                    session["server-decoder"] = create_decompressor(client_wb)
                    session["client-decoder"] = create_decompressor(server_wb)


            session["handshake-state"] = HANDSHAKE_STATE_OPEN

            return HTTP()/http_data
        

        # Handshake is done:
        if "original" not in metadata:
            return
        
        if "permessage-deflate" in session["extensions"]:
            is_server = True if metadata["original"][TCP].sport == session["server-port"] else False
            ws = WebSocket(bytes(data), extensions=session["extensions"], decoder = session["server-decoder"] if is_server else session["client-decoder"])
            return ws
        else:
            ws = WebSocket(bytes(data), extensions=session["extensions"])
            return ws