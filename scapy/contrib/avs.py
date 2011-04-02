#! /usr/bin/env python

# http://trac.secdev.org/scapy/ticket/82

# scapy.contrib.description = AVS WLAN Monitor Header
# scapy.contrib.status = loads

from scapy.packet import *
from scapy.fields import *
from scapy.layers.dot11 import *

AVSWLANPhyType =  { 0 : "Unknown",
                    1 : "FHSS 802.11 '97",
                    2 : "DSSS 802.11 '97", 
                    3 : "IR Baseband",
                    4 : "DSSS 802.11b",
                    5 : "PBCC 802.11b", 
                    6 : "OFDM 802.11g",
                    7 : "PBCC 802.11g",
                    8 : "OFDM 802.11a" }

AVSWLANEncodingType =  { 0 : "Unknown",
                         1 : "CCK",
                         2 : "PBCC",
                         3 : "OFDM"}

AVSWLANSSIType = { 0 : "None",
                   1 : "Normalized RSSI",
                   2 : "dBm",
                   3 : "Raw RSSI"}

AVSWLANPreambleType = { 0 : "Unknown",
                        1 : "Short",
                        2 : "Long" }


class AVSWLANHeader(Packet):
	""" iwpriv eth1 set_prismhdr 1 """
	name = "AVS WLAN Monitor Header"
	fields_desc = [   IntField("version",1),
	                  IntField("len",64),
	                 LongField("mactime",0),
	                 LongField("hosttime",0),
	              IntEnumField("phytype",0, AVSWLANPhyType),
	                  IntField("channel",0),
	                  IntField("datarate",0),
	                  IntField("antenna",0),
	                  IntField("priority",0),
	              IntEnumField("ssi_type",0, AVSWLANSSIType),
	            SignedIntField("ssi_signal",0),
	            SignedIntField("ssi_noise",0),
	              IntEnumField("preamble",0, AVSWLANPreambleType),
	              IntEnumField("encoding",0, AVSWLANEncodingType),
	                ]

bind_layers(AVSWLANHeader, Dot11)

