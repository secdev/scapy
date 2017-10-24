# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) 2016 Gauthier Sebaux

# scapy.contrib.description = ProfinetIO Real-Time Cyclic (RTC)
# scapy.contrib.status = loads

"""
PROFINET IO layers for scapy which correspond to Real-Time Cyclic data
"""

# external imports
from __future__ import absolute_import
import math
import struct

# Scapy imports
from scapy.all import Packet, bind_layers, Ether, UDP, Field, conf
from scapy.fields import BitEnumField, BitField, ByteField,\
        FlagsField,\
        PacketListField,\
        ShortField, StrFixedLenField,\
        XBitField, XByteField

# local imports
from scapy.contrib.pnio import ProfinetIO
from scapy.compat import orb
from scapy.modules.six.moves import range


#####################################
## PROFINET Real-Time Data Packets ##
#####################################

class PNIORealTimeIOxS(Packet):
    """IOCS and IOPS packets for PROFINET Real-Time payload"""
    name = "PNIO RTC IOxS"
    fields_desc = [
        BitEnumField("dataState", 1, 1, ["bad", "good"]),
        BitEnumField("instance", 0, 2, ["subslot", "slot", "device", "controller"]),
        XBitField("reserved", 0, 4),
        BitField("extension", 0, 1),
        ]

    def extract_padding(self, s):
        return None, s      # No extra payload


class PNIORealTimeRawData(Packet):
    """Raw data packets for PROFINET Real-Time payload.

    It's a configurable packet whose config only includes a fix length. The
    config parameter must then be a dict {"length": X}.

    PROFINET IO specification impose this packet to be followed with an IOPS
    (PNIORealTimeIOxS)"""
    __slots__ = ["_config"]
    name = "PNIO RTC Raw data"
    fields_desc = [
        StrFixedLenField("load", "", length_from=lambda p: p[PNIORealTimeRawData].length()),
        ]

    def __init__(self, _pkt="", post_transform=None, _internal=0, _underlayer=None, config=None, **fields):
        """
        length=None means that the length must be managed by the user. If it's
        defined, the field will always be length-long (padded with b"\\x00" if
        needed)
        """
        self._config = config
        Packet.__init__(self, _pkt=_pkt, post_transform=post_transform,
                        _internal=_internal, _underlayer=_underlayer, **fields)

    def copy(self):
        pkt = Packet.copy(self)
        pkt._config = self._config
        return pkt

    def clone_with(self, *args, **kargs):
        pkt = Packet.clone_with(self, *args, **kargs)
        pkt._config = self._config
        return pkt

    def length(self):
        """Get the length of the raw data"""
        # Manage the length of the packet if a length is provided
        return  self._config["length"]

# Make sure an IOPS follows a data
bind_layers(PNIORealTimeRawData, PNIORealTimeIOxS)



###############################
## PROFINET Real-Time Fields ##
###############################

class LowerLayerBoundPacketListField(PacketListField):
    """PacketList which binds each underlayer of packets to the current pkt"""
    def m2i(self, pkt, m):
        return self.cls(m, _underlayer=pkt)

class NotionalLenField(Field):
    """A len fields which isn't present in the machine representation, but is
    computed from a given lambda"""
    __slots__ = ["length_from", "count_from"]
    def __init__(self, name, default, length_from=None, count_from=None):
        Field.__init__(self, name, default)
        self.length_from = length_from
        self.count_from = count_from

    def addfield(self, pkt, s, val):
        return s   # Isn't present in the machine packet

    def getfield(self, pkt, s):
        val = None
        if self.length_from is not None:
            val = self.length_from(pkt, s)
        elif self.count_from is not None:
            val = self.count_from(pkt, s)
        return s, val


###############################
## PNIORealTime Configuration #
###############################

# conf.contribs["PNIO_RTC"] is a dict which contains data layout for each Ethernet
# communications. It must be formatted as such:
# {(Ether.src, Ether.dst): [(start, type, config), ...]}
# start: index of a data field from the END of the data buffer (-1, -2, ...)
# type: class to be instanciated to represent these data
# config: a config dict, given to the type class constructor
conf.contribs["PNIO_RTC"] = {}

def _get_ethernet(pkt):
    """Find the Ethernet packet of underlayer or None"""
    ether = pkt
    while ether is not None and not isinstance(ether, Ether):
        ether = ether.underlayer
    return ether

def pnio_update_config(config):
    """Update the PNIO RTC config"""
    conf.contribs["PNIO_RTC"].update(config)

def pnio_get_config(pkt):
    """Retrieve the config for a given communication"""
    # get the config based on the tuple (Ether.src, Ether.dst)
    ether = _get_ethernet(pkt)
    config = None
    if ether is not None and (ether.src, ether.dst) in conf.contribs["PNIO_RTC"]:
        config = conf.contribs["PNIO_RTC"][(ether.src, ether.dst)]

    return config


###############################
## PROFINET Real-Time Packet ##
###############################

def _pnio_rtc_guess_payload_class(_pkt, _underlayer=None, *args, **kargs):
    """A dispatcher for the packet list field which manage the configuration
    to fin dthe appropriate class"""
    config = pnio_get_config(_underlayer)

    if isinstance(config, list):
        # If we have a valid config, it's a list which describe each data
        # packets the rest being IOCS
        cur_index = -len(_pkt)
        for index, cls, params in config:
            if cur_index == index:
                return cls(_pkt, config=params, *args, **kargs)

        # Not a data => IOCS packet
        return PNIORealTimeIOxS(_pkt, *args, **kargs)
    else:
        # No config => Raw data which dissect the whole _pkt
        return PNIORealTimeRawData(_pkt,
                                   config={"length": len(_pkt)},
                                   *args, **kargs
                                  )


_PNIO_DS_FLAGS = [
    "primary",
    "redundancy",
    "validData",
    "reserved_1",
    "run",
    "no_problem",
    "reserved_2",
    "ignore",
    ]
class PNIORealTime(Packet):
    """PROFINET cyclic real-time"""
    name = "PROFINET Real-Time"
    fields_desc = [
        NotionalLenField("len", None, length_from=lambda p, s: len(s)),
        NotionalLenField("dataLen", None, length_from=lambda p, s: len(s[:-4].rstrip(b"\0"))),
        LowerLayerBoundPacketListField("data", [], _pnio_rtc_guess_payload_class, length_from=lambda p: p.dataLen),
        StrFixedLenField("padding", "", length_from=lambda p: p[PNIORealTime].padding_length()),
        ShortField("cycleCounter", 0),
        FlagsField("dataStatus", 0x35, 8, _PNIO_DS_FLAGS),
        ByteField("transferStatus", 0)
        ]
    overload_fields = {
        ProfinetIO: {"frameID": 0x8000},   # RT_CLASS_1
        }

    def padding_length(self):
        """Compute the length of the padding need for the ethernet frame"""
        fld, val = self.getfield_and_val("data")

        # use the len field if available to define the padding length, eg for
        # dissected packets
        pkt_len = self.getfieldval("len")
        if pkt_len is not None:
            return max(0, pkt_len - len(fld.addfield(self, b"", val)) - 4)

        if isinstance(self.underlayer, ProfinetIO) and \
                isinstance(self.underlayer.underlayer, UDP):
            return max(0, 12 - len(fld.addfield(self, b"", val)))
        else:
            return max(0, 40 - len(fld.addfield(self, b"", val)))

    @staticmethod
    def analyse_data(packets):
        """Analyse the data to find heuristical properties and determine
        location and type of data"""
        loc = PNIORealTime.find_data(packets)
        loc = PNIORealTime.analyse_profisafe(packets, loc)
        pnio_update_config(loc)
        return loc

    @staticmethod
    def find_data(packets):
        """Analyse a packet list to extract data offsets from packets data."""
        # a dictionary to count data offsets (ie != 0x80)
        # It's formatted: {(src, dst): (total, [count for offset in len])}
        heuristic = {}

        # Counts possible data locations
        # 0x80 are mainly IOxS and trailling 0x00s are just padding
        for pkt in packets:
            if PNIORealTime in pkt:
                pdu = bytes(pkt[PNIORealTime])[:-4].rstrip(b"\0")

                if (pkt.src, pkt.dst) not in heuristic:
                    heuristic[(pkt.src, pkt.dst)] = (0, [])

                total, counts = heuristic[(pkt.src, pkt.dst)]

                if len(counts) < len(pdu):
                    counts.extend([0 for _ in range(len(pdu) - len(counts))])

                for i in range(len(pdu)):
                    if orb(pdu[i]) != 0x80:
                        counts[i] += 1

                comm = (pkt.src, pkt.dst)
                heuristic[comm] = (total + 1, counts)

        # Determine data locations
        locations = {}
        for comm in heuristic:
            total, counts = heuristic[comm]
            length = len(counts)
            loc = locations[comm] = []
            start = None
            for i in range(length):
                if counts[i] > total // 2:   # Data if more than half is != 0x80
                    if start is None:
                        start = i
                else:
                    if start is not None:
                        loc.append((
                            start - length,
                            PNIORealTimeRawData,
                            {"length": i - start}
                            ))
                        start = None

        return locations

    @staticmethod
    def analyse_profisafe(packets, locations=None):
        """Analyse a packet list to find possible PROFISafe profils.

        It's based on an heuristical analysis of each payload to try to find
        CRC and control/status byte.

        locations: possible data locations. If not provided, analyse_pn_rt will
        be called beforehand. If not given, it calls in the same time
        analyse_data which update the configuration of the data field"""
        # get data locations and entropy of bytes
        if not locations:
            locations = PNIORealTime.find_data(packets)
        entropies = PNIORealTime.data_entropy(packets, locations)

        # Try to find at least 3 high entropy successive bytes (the CRC)
        for comm in entropies:
            entropy = dict(entropies[comm])  # Convert tuples to key => value

            for i in range(len(locations[comm])):
                # update each location with its value after profisafe analysis
                locations[comm][i] = \
                        PNIORealTime.analyse_one_profisafe_location(
                            locations[comm][i], entropy
                        )

        return locations

    @staticmethod
    def analyse_one_profisafe_location(location, entropy):
        """Analyse one PNIO RTC data location to find if its a PROFISafe

        :param location: location to analyse, a tuple (start, type, config)
        :param entropy: the entropy of each byte of the packet data
        :returns: the configuration associated with the data
        """
        start, klass, conf = location
        if conf["length"] >= 4:     # Minimal PROFISafe length
            succ_count = 0
            for j in range(start, start + conf["length"]):
                # Limit for a CRC is set to 6 bit of entropy min
                if j in entropy and entropy[j] >= 6:
                    succ_count += 1
                else:
                    succ_count = 0
            # PROFISafe profiles must end with at least 3 bytes of high entropy
            if succ_count >= 3: # Possible profisafe CRC
                return (
                    start,
                    Profisafe,
                    {"CRC": succ_count, "length": conf["length"]}
                    )
        # Not a PROFISafe profile
        return (start, klass, conf)

    @staticmethod
    def data_entropy(packets, locations=None):
        """Analyse a packet list to find the entropy of each data byte

        locations: possible data locations. If not provided, analyse_pn_rt will
        be called beforehand. If not given, it calls in the same time
        analyse_data which update the configuration of the data field"""
        if not locations:
            locations = PNIORealTime.find_data(packets)

        # Retrieve the entropy of each data byte, for each communication
        entropies = {}
        for comm in locations:
            if len(locations[comm]) > 0: # Doesn't append empty data
                entropies[comm] = []
                comm_packets = []

                # fetch all packets from the communication
                for pkt in packets:
                    if PNIORealTime in pkt and (pkt.src, pkt.dst) == comm:
                        comm_packets.append(
                            bytes(pkt[PNIORealTime])[:-4].rstrip(b"\0")
                            )

                # Get the entropy
                for start, dummy, conf in locations[comm]:
                    for i in range(start, start + conf["length"]):
                        entropies[comm].append(
                            (i, entropy_of_byte(comm_packets, i))
                            )

        return entropies

    @staticmethod
    def draw_entropy(packets, locations=None):
        """Plot the entropy of each data byte of PN RT communication"""
        import matplotlib.pyplot as plt
        import matplotlib.cm as cm
        entropies = PNIORealTime.data_entropy(packets, locations)

        rows = len(entropies)
        cur_row = 1
        for comm in entropies:
            index = []
            vals = []
            for i, ent in entropies[comm]:
                index.append(i)
                vals.append(ent)

            # Offsets the indexes to get the index from the beginning
            offset = -min(index)
            index = [i + offset for i in index]

            plt.subplot(rows, 1, cur_row)
            plt.bar(index, vals, 0.8, color="r")
            plt.xticks([i + 0.4 for i in index], index)
            plt.title("Entropy from %s to %s" % comm)
            cur_row += 1
            plt.ylabel("Shannon Entropy")

        plt.xlabel("Byte offset")   # x label only on the last row
        plt.legend()

        plt.tight_layout()
        plt.show()

def entropy_of_byte(packets, position):
    """Compute the entropy of a byte at a given offset"""
    counter = [0 for _ in range(256)]

    # Count each byte a appearance
    for pkt in packets:
        if -position <= len(pkt):     # position must be a negative index
            counter[orb(pkt[position])] += 1

    # Compute the Shannon entropy
    entropy = 0
    length = len(packets)
    for count in counter:
        if count > 0:
            ratio = float(count) / length
            entropy -= ratio * math.log(ratio, 2)

    return entropy

###############
## PROFISafe ##
###############

class XVarBytesField(XByteField):
    """Variable length bytes field, from 0 to 8 bytes"""
    __slots__ = ["length_from"]
    def __init__(self, name, default, length=None, length_from=None):
        self.length_from = length_from
        if length:
            self.length_from = lambda p, l=length: l
        Field.__init__(self, name, default, "!Q")

    def addfield(self, pkt, s, val):
        length = self.length_from(pkt)
        return s + struct.pack(self.fmt, self.i2m(pkt, val))[8-length:]

    def getfield(self, pkt, s):
        length = self.length_from(pkt)
        val = struct.unpack(self.fmt, b"\x00"*(8 - length) + s[:length])[0]
        return  s[length:], self.m2i(pkt, val)


class Profisafe(PNIORealTimeRawData):
    """PROFISafe profil to be encapsulated inside the PNRT.data list.

    It's a configurable packet whose config includes a fix length, and a CRC
    length. The config parameter must then be a dict {"length": X, "CRC": Y}.
    """
    name = "PROFISafe"
    fields_desc = [
        StrFixedLenField("load", "", length_from=lambda p: p[Profisafe].data_length()),
        XByteField("Control_Status", 0),
        XVarBytesField("CRC", 0, length_from=lambda p: p[Profisafe].crc_length())
        ]
    def data_length(self):
        """Return the length of the data"""
        ret = self.length() - self.crc_length() - 1
        return  ret

    def crc_length(self):
        """Return the length of the crc"""
        return self._config["CRC"]

