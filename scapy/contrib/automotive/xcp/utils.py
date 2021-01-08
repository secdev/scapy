# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Tabea Spahn <tabea.spahn@e-mundo.de>
# This program is published under a GPLv2 license

# scapy.contrib.status = skip

import struct
from logging import warning

from scapy.config import conf
from scapy.fields import StrLenField
from scapy.volatile import RandBin, RandNum


def get_max_cto():
    max_cto = conf.contribs['XCP']['MAX_CTO']
    if max_cto:
        return max_cto

    warning("Define conf.contribs['XCP']['MAX_CTO'].")
    raise KeyError("conf.contribs['XCP']['MAX_CTO'] not defined")


def get_max_dto():
    max_dto = conf.contribs['XCP']['MAX_DTO']
    if max_dto:
        return max_dto
    else:
        warning("Define conf.contribs['XCP']['MAX_DTO'].")
        raise KeyError("conf.contribs['XCP']['MAX_DTO'] not defined")


def get_ag():
    address_granularity = conf.contribs['XCP']['Address_Granularity_Byte']
    if address_granularity and address_granularity in [1, 2, 4]:
        return address_granularity
    else:
        warning("Define conf.contribs['XCP']['Address_Granularity_Byte']."
                "Assign either 1, 2 or 4")
        return 1


# With TIMESTAMP_MODE and TIMESTAMP_TICKS at GET_DAQ_RESOLUTION_INFO,
# the slave informs the master about the Type of Timestamp Field
# the slave will use when transferring DAQ Packets to the master.
# The master has to use the same Type of Timestamp Field when transferring
# STIM Packets to the slave. TIMESTAMP_MODE and TIMEPSTAMP_TICKS contain
# information on the resolution of the data transfer clock.
def get_timestamp_length():
    return conf.contribs['XCP']['timestamp_size']


def identification_field_needs_alignment():
    try:
        identification_field_type_0 = conf.contribs['XCP'][
            'identification_field_type_0']
        identification_field_type_1 = conf.contribs['XCP'][
            'identification_field_type_1']
        if identification_field_type_1 == 1 and \
                identification_field_type_0 == 1:
            # relative odt with daq as word (aligned)
            return True
        return False
    except KeyError:
        return False


def get_daq_length():
    try:
        identification_field_type_0 = conf.contribs['XCP'][
            'identification_field_type_0']
        identification_field_type_1 = conf.contribs['XCP'][
            'identification_field_type_1']

        if identification_field_type_1 == 0 and \
                identification_field_type_0 == 0:
            # absolute odt number
            return 0
        if identification_field_type_1 == 0 and \
                identification_field_type_0 == 1:
            # relative odt with daq as byte
            return 1
        # relative odt with daq as word
        return 2
    except KeyError:
        return 0


def get_daq_data_field_length():
    try:
        data_length = get_max_dto()
    except KeyError:
        return 0
    data_length -= 1  # pid
    if identification_field_needs_alignment():
        data_length -= 1
    data_length -= get_daq_length()

    return data_length


# Idea taken from scapy/scapy/contrib/dce_rpc.py
class XCPEndiannessField(object):
    """Field which changes the endianness of a sub-field"""
    __slots__ = ["fld"]

    def __init__(self, fld):
        self.fld = fld

    def set_endianness(self):
        """Add the endianness to the format"""
        byte_oder = conf.contribs['XCP']['byte_order']
        endianness = ">" if byte_oder == 1 else "<"

        self.fld.fmt = endianness + self.fld.fmt[1:]
        self.fld.struct = struct.Struct(self.fld.fmt)

    def getfield(self, pkt, s):
        self.set_endianness()

        return self.fld.getfield(pkt, s)

    def addfield(self, pkt, s, val):
        self.set_endianness()
        return self.fld.addfield(pkt, s, val)

    def __getattr__(self, attr):
        return getattr(self.fld, attr)


class StrVarLenField(StrLenField):
    def randval(self):
        return RandBin(RandNum(0, self.max_length() or 1200))
