from scapy.fields import BitField, FlagsField, ByteEnumField, XShortField, XByteField, ByteEnumField, XIntField
from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import Ether

class AOE(Packet):
	name = "ATA over Ethernet"
	fields_desc = [	BitField("version", 1, 4),
			FlagsField("flags", 0, 4, ["Response", "Error", "r1", "r2"]),
			ByteEnumField("error", 0, {1:"Unrecognized command code", 2:"Bad argument parameter", 3:"Device unavailable", 4:"Config string present", 5:"Unsupported exception", 6:"Target is reserved"}),
			XShortField("major", 0xFFFF),
			XByteField("minor", 0xFF),
			ByteEnumField("command", 1, {0:"Issue ATA Command", 1:"Query Config Information", 2:"Mac Mask List", 3:"Reserve / Release"}),
			XIntField("tag", 0),
			XIntField("buffer", 0),
			XIntField("sector", 0),
			XIntField("config_length", 0),
			XIntField("config", 0)
			#ConditionnalField
			]

bind_layers(Ether, AOE, type=0x88A2)

class IssueATACommand(Packet):
	name = "Issue ATA Command"
	fields_desc = [	FlagsField("flags", 0, 8, "zezdzzaw"),
			XByteField("err_feature", 0),
			ByteField("sector_count", 0),
			XByteField("cmd_status", 0),
			XByteField("lba0", 0),
			XByteField("lba0", 1),
			XByteField("lba0", 2),
			XByteField("lba0", 3),
			XByteField("lba0", 4),
			XByteField("lba0", 5),
			XShortField("reserved", 0),
			StrLenField("data", "", length_from = lambda x: x.sector_count * 512)
			]

class QueryConfigInformation(Packet):
	name = "Query Config Information"
	fields_desc = [	ShortField("buffer_count", 0),
			ShortField("firmware", 0),
			ByteField("sector_count", 0),
			BiteField("aoe", 0, 4),
			BiteEnumField("ccmd", 0, 4, {0:"Read config string", 1:"Test config string", 2:"Test config string prefix", 3:"Set config string", 4:"Force set config string"}),
			ShortField("config_length", 0),
			StrLenField("config", "", length_from = lambda x: x.config_length)
			]
