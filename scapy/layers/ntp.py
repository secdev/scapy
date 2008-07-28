## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP

# seconds between 01-01-1900 and 01-01-1970
ntp_basetime = 2208988800

class TimeStampField(BitField):
    def __init__(self, name, default, size):
        BitField.__init__(self, name, default, size)
        self.size  = size
    def getfield(self, pkt, s):
        s,timestamp = BitField.getfield(self, pkt, s)

        if timestamp:
            # timestamp is a 64 bits field :
            #  + first 32 bits : number of seconds since 1900
            #  + last 32 bits  : fraction part
            timestamp >>= 32
            timestamp -= ntp_basetime
            
            from time import gmtime, strftime
            b = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime(timestamp))
        else:
            b = 'None'
        
        return s, b
    def addfield(self, pkt, s, val):
        t = -1
        if type(val) is str:
            from time import strptime, mktime
            t = int(mktime(strptime(val))) + ntp_basetime + 3600
        else:
            if val == -1:
                from time import time
                t = int(time()) + ntp_basetime
            else:
                t = val
        t <<= 32
        return BitField.addfield(self,pkt,s, t)


class NTP(Packet):
    # RFC 1769
    name = "NTP"
    fields_desc = [ 
         BitEnumField('leap', 0, 2,
                      { 0: 'nowarning',
                        1: 'longminute',
                        2: 'shortminute',
                        3: 'notsync'}),
         BitField('version', 3, 3),
         BitEnumField('mode', 3, 3,
                      { 0: 'reserved',
                        1: 'sym_active',
                        2: 'sym_passive',
                        3: 'client',
                        4: 'server',
                        5: 'broadcast',
                        6: 'control',
                        7: 'private'}),
         BitField('stratum', 2, 8),
         BitField('poll', 0xa, 8),          ### XXX : it's a signed int
         BitField('precision', 0, 8),       ### XXX : it's a signed int
         FloatField('delay', 0, 32),
         FloatField('dispersion', 0, 32),
         IPField('id', "127.0.0.1"),
         TimeStampField('ref', 0, 64),
         TimeStampField('orig', -1, 64),  # -1 means current time
         TimeStampField('recv', 0, 64),
         TimeStampField('sent', -1, 64) 
         ]
    def mysummary(self):
        return self.sprintf("NTP v%ir,NTP.version%, %NTP.mode%")


bind_layers( UDP,           NTP,           dport=123, sport=123)
