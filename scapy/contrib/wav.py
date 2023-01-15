"""
Implement WAV

https://en.wikipedia.org/wiki/WAV
https://sites.google.com/site/musicgapi/technical-documents/wav-file-format
https://www.javatips.net/api/riff-wav-for-java-master/com.skratchdot.riff.wav/src/com/skratchdot/riff/wav/impl/ChunkCueImpl.java
https://www.recordingblogs.com/wiki/list-chunk-of-a-wave-file
https://homspace.nl/samplerbox/WAVE%20File%20Format.htm
https://www.lim.di.unimi.it/IEEE/VROS/RIFF.HTM
http://soundfile.sapp.org/doc/WaveFormat/
https://github.com/steelegbr/wave-chunk-parser/blob/main/wave_chunk_parser/chunks.py
"""
import struct
from scapy.fields import (
    LEShortField,
    LEIntField,
    StrField,
    LEFieldLenField,
    PacketListField,
)
from scapy.packet import Packet
from scapy.utils import hexdump


class WAVHeader(Packet):
    """WAV Header"""

    name = "WAV Header"
    fields_desc = [
        StrField("riff_marker", "RIFF"),
        LEIntField("file_size", None),  # 4 bytes
        StrField("wave_marker", "WAVE"),
        # Here we need to pick one or more of the list
    ]

    def post_build(self, pkt, pay):
        """Adjust the values"""
        if self.file_size is None and pay:
            size_wav = len(pay)
            pkt = (
                pkt[:4] + struct.pack("I", size_wav) + pkt[8:]
            )  # Size of the BMP file (bytes header + bytes data)

        return pkt + pay


class ChunkFmt(Packet):
    """WAV Chunk Fmt"""

    name = "Chunk Fmt"
    fields_desc = [
        StrField("id", "fmt "),
        LEIntField("fmt_size", 16),  # 4 bytes
        LEShortField("audio_format", default=1),  # 2 bytes
        LEShortField("num_channels", default=1),  # 2 bytes
        LEIntField("sample_rate", default=0xAC44),  # 4 bytes
        LEIntField("byte_rate", default=0x015888),  # 4 bytes
        LEShortField("block_align", default=2),  # 2 bytes
        LEShortField("bits_per_sample", default=16),  # 2 bytes
    ]


class ChunkData(Packet):
    """WAV Chunk Data"""

    name = "Chunk Data"
    fields_desc = [
        StrField("id", "data"),
        LEFieldLenField("data_size", default=None, length_of="data_data", fmt="<I"),
        StrField("data_data", default=""),
    ]


class ChunkFact(Packet):
    """WAV Chunk Fact"""

    name = "Chunk Fact"
    fields_desc = [
        StrField("id", "fact"),
        LEFieldLenField("fact_size", default=0, length_of="fact_data"),
        StrField("fact_data", default=""),
    ]


class ChunkSilent(Packet):
    """WAV Silent Chunk"""

    name = "Chunk Silent"
    fields_desc = [
        StrField("id", "slnt"),
        LEFieldLenField("slnt_size", default=0, length_of="slnt_data", fmt="<I"),
        StrField("slnt_data", default=""),
    ]


class ChunkWaveList(Packet):
    """WAV List"""

    name = "Chunk Wave List"
    fields_desc = [
        StrField("id", "wavl"),
        LEFieldLenField("wavl_size", default=0, length_of="wavl_data", fmt="<I"),
        StrField("wavl_data", default=""),
    ]


class ChunkCuePoint(Packet):
    name = "Cue Point"
    fields_desc = [
        # cue_data -> this is 24 bytes
        LEIntField("id", default=0),  # 4 bytes
        LEIntField("position", default=0),  # 4 bytes
        LEIntField("data_chunk_id", default=0),  # 4 bytes
        LEIntField("chunk_start", default=0),  # 4 bytes
        LEIntField("block_start", default=0),  # 4 bytes
        LEIntField("sample_offset", default=0),  # 4 bytes
    ]


class ChunkCue(Packet):
    """WAV Cue"""

    name = "Chunk Cue"
    fields_desc = [
        StrField("id", "cue"),
        LEFieldLenField(
            "cue_size",
            default=0,
            length_of="cue_points",
            adjust=lambda pkt, x: x + 4,
            fmt="<I",
        ),  # ChunkCueSize = 4 + (NumCuePoints * 24)
        PacketListField(
            "cue_points", [], ChunkCuePoint, count_from=lambda pkt: (pkt.len % 24)
        ),
    ]


class ChunkSegment(Packet):
    name = "Segment"
    fields_desc = [
        LEIntField("id", default=0),  # 4 bytes
        LEIntField("length", default=0),  # 4 bytes
        LEIntField("repeats", default=0),  # 4 bytes
    ]


class ChunkPlaylist(Packet):
    """WAV Playlist"""

    name = "Chunk Playlist"
    fields_desc = [
        StrField("id", "plst"),
        LEFieldLenField(
            "plst_size",
            default=0,
            length_of="segments",
            adjust=lambda pkt, x: x + 4,
            fmt="<I",
        ),  # ChunkPlaylistSize = 4 + (number_of_segments * 12)
        PacketListField(
            "segments", [], ChunkSegment, count_from=lambda pkt: (pkt.len % 12)
        ),
    ]


class ChunkList(Packet):
    """WAV List"""

    name = "Chunk List"
    fields_desc = [
        StrField("id", "list"),
        LEFieldLenField(
            "list_size",
            default=0,
            length_of="list_data",
            adjust=lambda pkt, x: x + 4,
            fmt="<I",
        ),
        StrField("type", "adtl"),
        StrField("list_data", default=""),
    ]


def test():
    payload_test = ChunkData()
    payload_test.data_data = ""
    bmp_test = WAVHeader() / ChunkFmt() / payload_test

    generated = hexdump(bmp_test, dump=True)

    # Smallest possible WAV file (that is valid)
    if (
        generated
        != """0000  52 49 46 46 20 00 00 00 57 41 56 45 66 6D 74 20  RIFF ...WAVEfmt 
0010  10 00 00 00 01 00 01 00 44 AC 00 00 88 58 01 00  ........D....X..
0020  02 00 10 00 64 61 74 61 00 00 00 00              ....data...."""
    ):
        raise ValueError("Generator error")

    payload = ChunkData()
    payload.data_data = bytes.fromhex(
        "24 17 1e f3 3c 13 3c 14 16 f9 18 f9 34 e7 23 a6 3c f2 24 f2 11 ce 1a 0d"
    )
    bmp_test = WAVHeader() / ChunkFmt() / payload

    # Check data field align
    generated = hexdump(bmp_test, dump=True)
    if (
        generated
        != """0000  52 49 46 46 38 00 00 00 57 41 56 45 66 6D 74 20  RIFF8...WAVEfmt 
0010  10 00 00 00 01 00 01 00 44 AC 00 00 88 58 01 00  ........D....X..
0020  02 00 10 00 64 61 74 61 18 00 00 00 24 17 1E F3  ....data....$...
0030  3C 13 3C 14 16 F9 18 F9 34 E7 23 A6 3C F2 24 F2  <.<.....4.#.<.$.
0040  11 CE 1A 0D                                      ...."""
    ):
        raise ValueError("Generator error")

