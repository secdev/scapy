"""
Implement WAV

https://en.wikipedia.org/wiki/WAV
https://sites.google.com/site/musicgapi/technical-documents/wav-file-format
https://www.javatips.net/api/riff-wav-for-java-master/com.skratchdot.riff.wav/src/com/skratchdot/riff/wav/impl/ChunkCueImpl.java
https://www.recordingblogs.com/wiki/list-chunk-of-a-wave-file
https://homspace.nl/samplerbox/WAVE%20File%20Format.htm
https://www.lim.di.unimi.it/IEEE/VROS/RIFF.HTM
"""
import struct
from scapy.fields import LEShortField, LEIntField, StrField, LEFieldLenField, PacketListField
from scapy.packet import Packet, bind_layers

class WAVHeader(Packet):
    """ WAV Header """

    name = "WAV Header"
    fields_desc = [
        StrField("riff_marker", "RIFF"),
        LEIntField("file_size", 32), # 4 bytes
        StrField("wave_marker", "WAVE"),
        # Here we need to pick one or more of the list

    ]

class ChunkFmt(Packet):
    """ WAV Chunk Fmt """
    name = "Chunk Fmt"
    fields_desc = [
        StrField("id", "fmt"),
        LEShortField("audio_format", default=0),
        LEShortField("num_channels", default=0),
        LEIntField("sample_rate", default=0),
        LEIntField("byte_rate", default=0),
        LEShortField("block_align", default=0),
        LEShortField("bits_per_sample", default=0),
    ]

class ChunkData(Packet):
    """ WAV Chunk Data """
    name = "Chunk Data"
    fields_desc = [
        StrField("id", "data"),
        LEFieldLenField("data_size", default=0, length_of="data_data"),
        StrField("data_data", default="")
    ]

class ChunkFact(Packet):
    """ WAV Chunk Fact """
    name = "Chunk Fact"
    fields_desc = [
        StrField("id", "fact"),
        LEFieldLenField("fact_size", default=0, length_of="fact_data"),
        StrField("fact_data", default="")
    ]

class ChunkSilent(Packet):
    """ WAV Silent Chunk """
    name = "Chunk Silent"
    fields_desc = [
        StrField("id", "slnt"),
        LEFieldLenField("slnt_size", default=0, length_of="slnt_data"),
        StrField("slnt_data", default="")
    ]

class ChunkWaveList(Packet):
    """ WAV List """
    name = "Chunk Wave List"
    fields_desc = [
        StrField("id", "wavl"),
        LEFieldLenField("wavl_size", default=0, length_of="wavl_data"),
        StrField("wavl_data", default="")
    ]

class ChunkCuePoint(Packet):
    name = "Cue Point"
    fields_desc = [
        # cue_data -> this is 24 bytes
        LEIntField("id", default=0), # 4 bytes
        LEIntField("position", default=0), # 4 bytes
        LEIntField("data_chunk_id", default=0), # 4 bytes
        LEIntField("chunk_start", default=0), # 4 bytes
        LEIntField("block_start", default=0), # 4 bytes
        LEIntField("sample_offset", default=0), # 4 bytes
    ]

class ChunkCue(Packet):
    """ WAV Cue """
    name = "Chunk Cue"
    fields_desc = [
        StrField("id", "cue"),
        LEFieldLenField("cue_size", default=0, length_of="cue_points", adjust=lambda pkt, x: x + 4), # ChunkDataSize = 4 + (NumCuePoints * 24)

        PacketListField(
            "cue_points",
            [],
            ChunkCuePoint,
            count_from=lambda pkt: (
                pkt.len % 24
            )
        ),
    ]

class ChunkSegment(Packet):
    name = "Segment"
    fields_desc = [
        LEIntField("id", default=0), # 4 bytes
        LEIntField("length", default=0), # 4 bytes
        LEIntField("repeats", default=0), # 4 bytes
    ]

class ChunkPlaylist(Packet):
    """ WAV Playlist """
    name = "Chunk Playlist"
    fields_desc = [
        StrField("id", "plst"),
        LEFieldLenField("plst_size", default=0, length_of="segments", adjust=lambda pkt, x: x + 4), # ChunkDataSize = 4 + (number_of_segments * 12)

        PacketListField(
            "segments",
            [],
            ChunkSegment,
            count_from=lambda pkt: (
                pkt.len % 12
            )
        ),
    ]


class ChunkList(Packet):
    """ WAV List """
    name = "Chunk List"
    fields_desc = [
        StrField("id", "list"),
        LEFieldLenField("list_size", default=0, length_of="list_data", adjust=lambda pkt, x: x + 4),
        StrField("type", "adtl"),
        StrField("list_data", default="")
    ]

