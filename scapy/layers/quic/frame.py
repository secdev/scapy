# Do not import QUIC here to avoid circular import

from scapy.layers.quic.basefields import (
    QuicVarEnumField,
    QuicVarIntField,
    QuicVarLenField,
    _quic_frames,
)

from scapy.packet import (
    Packet,
)

from scapy.fields import (
    BitEnumField,
    BitField,
    FieldLenField,
    IntField,
    PacketField,
    PacketListField,
    StrLenField,
    XByteField,
)


class Frame(Packet):
    """
    Base class for QUIC frames.
    """
    match_subclass = True

    name = "QUIC Frame"
    fields_desc = [
        BitEnumField("FrameType", None, 8, _quic_frames),
    #     # PacketField("Payload", None, Packet),  # Placeholder for frame payload
    ]

    def mysummary(self):
        return self.name
    
    def extract_padding(self, s):
        return b'', s

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Returns the right class for the given data.
        """
        if _pkt:
            type = _pkt[0]
            return {
                0x00: QUIC_Frame_PADDING,
                0x01: QUIC_Frame_PING,
                0x02: QUIC_Frame_ACK,
                # 0x03: QUIC_Frame_ACK_ECN,
                # 0x04: QUIC_Frame_RESET_STREAM,
                # 0x05: QUIC_Frame_STOP_SENDING,
                0x06: QUIC_Frame_CRYPTO,
                # 0x07: QUIC_Frame_NEW_TOKEN,
                # 0x08: QUIC_Frame_STREAM,
                # 0x10: QUIC_Frame_MAX_DATA,
                # 0x11: QUIC_Frame_MAX_STREAM_DATA,
                # 0x12: QUIC_Frame_MAX_STREAMS,
                # 0x14: QUIC_Frame_DATA_BLOCKED,
                # 0x15: QUIC_Frame_STREAM_DATA_BLOCKED,
                # 0x16: QUIC_Frame_STREAMS_BLOCKED,
                # 0x18: QUIC_Frame_NEW_CONNECTION_ID,
                # 0x19: QUIC_Frame_RETIRE_CONNECTION_ID,
                # 0x1A: QUIC_Frame_PATH_CHALLENGE,
                # 0x1B: QUIC_Frame_PATH_RESPONSE,
                # 0x1C: QUIC_Frame_CONNECTION_CLOSE,
                # 0x1E: QUIC_Frame_HANDSHAKE_DONE,
            }[type]
        return None

class QUIC_Frame_PADDING(Frame):
    """
    QUIC Padding Frame.
    """
    name = "QUIC Frame - Padding"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x00, _quic_frames),
        IntField("PaddingLength", 0),
    ]

    def extract_padding(self, s):
        count = 0
        for b in s:
            if b == 0x00:
                count += 1
            else:
                break
        self.PaddingLength = count
        return s[:count], s[count:]

class QUIC_Frame_PING(Frame):
    """
    QUIC Ping Frame.
    """
    name = "QUIC Frame - Ping"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x01, _quic_frames),
    ]

class QUIC_Frame_ACK(Frame):
    """
    QUIC ACK Frame.
    """
    name = "QUIC Frame - ACK"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x02, _quic_frames),
        QuicVarIntField("LargestAcknowledged", 0),
        QuicVarIntField("AckDelay", 0),
        QuicVarIntField("AckRangeCount", 0),
        QuicVarIntField("FirstAckRange", 0),
    ]

# class QUIC_Frame_RESET_STREAM(Frame):
#     """
#     QUIC Reset Stream Frame.
#     """
#     name = "QUIC Frame - Reset Stream"
#     fields_desc = [
#         BitEnumField("FrameType", 0x04, 8, _quic_frames),
#         IntField("StreamID", 0),
#         IntField("ErrorCode", 0),
#         IntField("FinalSize", 0),
#     ]

# class QUIC_Frame_STOP_SENDING(Frame):
#     """
#     QUIC Stop Sending Frame.
#     """
#     name = "QUIC Frame - Stop Sending"
#     fields_desc = [
#         BitEnumField("FrameType", 0x05, 8, _quic_frames),
#         IntField("StreamID", 0),
#         IntField("ErrorCode", 0),
#     ]

class QUIC_Frame_CRYPTO(Frame):
    """
    QUIC Crypto Frame.
    """
    name = "QUIC Frame - Crypto"
    fields_desc = [
        QuicVarEnumField("FrameType", 0x06, _quic_frames),
        QuicVarIntField("Offset", 0),
        QuicVarLenField("Length", None, fmt="H", length_of="Data"),
        StrLenField("Data", "", length_from=lambda pkt: pkt.Length),
    ]

# class QUIC_Frame_NEW_TOKEN(Frame):
#     """
#     QUIC New Token Frame.
#     """
#     name = "QUIC Frame - New Token"
#     fields_desc = [
#         BitEnumField("FrameType", 0x07, 8, _quic_frames),
#         FieldLenField("TokenLength", None, fmt="H", length_of="Token"),
#         StrLenField("Token", "", length_from=lambda pkt: pkt.TokenLength),
#     ]

# class QUIC_Frame_STREAM(Frame):
#     """
#     QUIC Stream Frame.
#     """
#     name = "QUIC Frame - Stream"
#     fields_desc = [
#         BitEnumField("FrameType", 0x08, 8, _quic_frames),
#         IntField("StreamID", 0),
#         BitField("Fin", 0, 1),
#         BitField("Offset", 0, 1),
#         FieldLenField("Length", None, fmt="H", length_of="Data"),
#         StrLenField("Data", "", length_from=lambda pkt: pkt.Length),
#     ]

# class QUIC_Frame_MAX_DATA(Frame):
#     """
#     QUIC Max Data Frame.
#     """
#     name = "QUIC Frame - Max Data"
#     fields_desc = [
#         BitEnumField("FrameType", 0x10, 8, _quic_frames),
#         IntField("MaxData", 0),
#     ]

# class QUIC_Frame_MAX_STREAM_DATA(Frame):
#     """
#     QUIC Max Stream Data Frame.
#     """
#     name = "QUIC Frame - Max Stream Data"
#     fields_desc = [
#         BitEnumField("FrameType", 0x11, 8, _quic_frames),
#         IntField("StreamID", 0),
#         IntField("MaxStreamData", 0),
#     ]

# class QUIC_Frame_MAX_STREAMS(Frame):
#     """
#     QUIC Max Streams Frame.
#     """
#     name = "QUIC Frame - Max Streams"
#     fields_desc = [
#         BitEnumField("FrameType", 0x12, 8, _quic_frames),
#         BitField("StreamType", 0, 1),  # 0 for unidirectional, 1 for bidirectional
#         IntField("MaxStreams", 0),
#     ]

# class QUIC_Frame_DATA_BLOCKED(Frame):
#     """
#     QUIC Data Blocked Frame.
#     """
#     name = "QUIC Frame - Data Blocked"
#     fields_desc = [
#         BitEnumField("FrameType", 0x14, 8, _quic_frames),
#         IntField("DataLimit", 0),
#     ]

# class QUIC_Frame_STREAM_DATA_BLOCKED(Frame):
#     """
#     QUIC Stream Data Blocked Frame.
#     """
#     name = "QUIC Frame - Stream Data Blocked"
#     fields_desc = [
#         BitEnumField("FrameType", 0x15, 8, _quic_frames),
#         IntField("StreamID", 0),
#         IntField("DataLimit", 0),
#     ]

# class QUIC_Frame_STREAMS_BLOCKED(Frame):
#     """
#     QUIC Streams Blocked Frame.
#     """
#     name = "QUIC Frame - Streams Blocked"
#     fields_desc = [
#         BitEnumField("FrameType", 0x16, 8, _quic_frames),
#         BitField("StreamType", 0, 1),  # 0 for unidirectional, 1 for bidirectional
#         IntField("StreamLimit", 0),
#     ]

# class QUIC_Frame_NEW_CONNECTION_ID(Frame):
#     """
#     QUIC New Connection ID Frame.
#     """
#     name = "QUIC Frame - New Connection ID"
#     fields_desc = [
#         BitEnumField("FrameType", 0x18, 8, _quic_frames),
#         IntField("SequenceNumber", 0),
#         FieldLenField("ConnectionIDLength", None, fmt="B", length_of="ConnectionID"),
#         StrLenField("ConnectionID", "", length_from=lambda pkt: pkt.ConnectionIDLength),
#         IntField("RetirePriorTo", 0),
#     ]

# class QUIC_Frame_RETIRE_CONNECTION_ID(Frame):
#     """
#     QUIC Retire Connection ID Frame.
#     """
#     name = "QUIC Frame - Retire Connection ID"
#     fields_desc = [
#         BitEnumField("FrameType", 0x19, 8, _quic_frames),
#         IntField("SequenceNumber", 0),
#     ]

# class QUIC_Frame_PATH_CHALLENGE(Frame):
#     """
#     QUIC Path Challenge Frame.
#     """
#     name = "QUIC Frame - Path Challenge"
#     fields_desc = [
#         BitEnumField("FrameType", 0x1A, 8, _quic_frames),
#         StrLenField("Data", "", length_from=lambda pkt: len(pkt) - 1),
#     ]

# class QUIC_Frame_PATH_RESPONSE(Frame):
#     """
#     QUIC Path Response Frame.
#     """
#     name = "QUIC Frame - Path Response"
#     fields_desc = [
#         BitEnumField("FrameType", 0x1B, 8, _quic_frames),
#         StrLenField("Data", "", length_from=lambda pkt: len(pkt) - 1),
#     ]

# class QUIC_Frame_CONNECTION_CLOSE(Frame):
#     """
#     QUIC Connection Close Frame.
#     """
#     name = "QUIC Frame - Connection Close"
#     fields_desc = [
#         BitEnumField("FrameType", 0x1C, 8, _quic_frames),
#         IntField("ErrorCode", 0),
#         StrLenField("ReasonPhrase", "", length_from=lambda pkt: len(pkt) - 1 - 4),
#         IntField("FrameType", 0),  # Optional frame type that caused the close
#     ]

# class QUIC_Frame_HANDSHAKE_DONE(Frame):
#     """
#     QUIC Handshake Done Frame.
#     """
#     name = "QUIC Frame - Handshake Done"
#     fields_desc = [
#         BitEnumField("FrameType", 0x1E, 8, _quic_frames),
#         StrLenField("Payload", "", length_from=lambda pkt: len(pkt) - 1),
#     ]
