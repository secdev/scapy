import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import XShortField,  LEShortField, \
    BitField, BitEnumField, PacketField, ConditionalField, \
    ByteField
from scapy.layers.inet import TCP, UDP

__author__ = 'Nicholas Rodofile'

'''
# Copyright 2014-2016 N.R Rodofile

Licensed under the GPLv3.
This program is free software: you can redistribute it and/or modify it under the terms 
of the GNU General Public License as published by the Free Software Foundation, either 
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details. You should have received a copy of 
the GNU General Public License along with this program. If not, see 
http://www.gnu.org/licenses/.
'''


bitState = {1: "SET", 0: "UNSET"}
stations = {1: "MASTER", 0: "OUTSTATION"}

MASTER = 1
OUTSTATION = 0
SET = 1
UNSET = 0
dnp3_port = 20000

Transport_summary = "Seq:%DNP3Transport.SEQUENCE% "
Application_Rsp_summary = "Response %DNP3ApplicationResponse.FUNC_CODE% "
Application_Req_summary = "Request %DNP3ApplicationRequest.FUNC_CODE% "
DNP3_summary = "From %DNP3.SOURCE% to %DNP3.DESTINATION% "

_codeTemplate = '''// Automatically generated CRC function
// %(poly)s
%(crcType)s
%(name)s(%(dataType)s *data, int len, %(crcType)s crc)
{
    static const %(crcType)s table[256] = {%(crcTable)s
    };
    %(preCondition)s
    while (len > 0)
    {
        crc = %(crcAlgor)s;
        data++;
        len--;
    }%(postCondition)s
    return crc;
}
'''

class Crc:
    def __init__(self, poly, initCrc=~0, rev=True, xorOut=0, initialize=True):
        if not initialize:
            # Don't want to perform the initialization when using new or copy
            # to create a new instance.
            return

        (sizeBits, initCrc, xorOut) = _verifyParams(poly, initCrc, xorOut)
        self.digest_size = sizeBits//8
        self.initCrc = initCrc
        self.xorOut = xorOut

        self.poly = poly
        self.reverse = rev

        (crcfun, table) = _mkCrcFun(poly, sizeBits, initCrc, rev, xorOut)
        self._crc = crcfun
        self.table = table

        self.crcValue = self.initCrc


    def __str__(self):
        lst = []
        lst.append('poly = 0x%X' % self.poly)
        lst.append('reverse = %s' % self.reverse)
        fmt = '0x%%0%dX' % (self.digest_size*2)
        lst.append('initCrc  = %s' % (fmt % self.initCrc))
        lst.append('xorOut   = %s' % (fmt % self.xorOut))
        lst.append('crcValue = %s' % (fmt % self.crcValue))
        return '\n'.join(lst)

    def new(self, arg=None):
        '''Create a new instance of the Crc class initialized to the same
        values as the original instance.  The current CRC is set to the initial
        value.  If a string is provided in the optional arg parameter, it is
        passed to the update method.
        '''
        n = Crc(poly=None, initialize=False)
        n._crc = self._crc
        n.digest_size = self.digest_size
        n.initCrc = self.initCrc
        n.xorOut = self.xorOut
        n.table = self.table
        n.crcValue = self.initCrc
        n.reverse = self.reverse
        n.poly = self.poly
        if arg is not None:
            n.update(arg)
        return n

    def copy(self):
        '''Create a new instance of the Crc class initialized to the same
        values as the original instance.  The current CRC is set to the current
        value.  This allows multiple CRC calculations using a common initial
        string.
        '''
        c = self.new()
        c.crcValue = self.crcValue
        return c

    def update(self, data):
        '''Update the current CRC value using the string specified as the data
        parameter.
        '''
        self.crcValue = self._crc(data, self.crcValue)

    def digest(self):
        '''Return the current CRC value as a string of bytes.  The length of
        this string is specified in the digest_size attribute.
        '''
        n = self.digest_size
        crc = self.crcValue
        lst = []
        while n > 0:
            lst.append(chr(crc & 0xFF))
            crc = crc >> 8
            n -= 1
        lst.reverse()
        return ''.join(lst)

    def hexdigest(self):
        '''Return the current CRC value as a string of hex digits.  The length
        of this string is twice the digest_size attribute.
        '''
        n = self.digest_size
        crc = self.crcValue
        lst = []
        while n > 0:
            lst.append('%02X' % (crc & 0xFF))
            crc = crc >> 8
            n -= 1
        lst.reverse()
        return ''.join(lst)

    def generateCode(self, functionName, out, dataType=None, crcType=None):
        '''Generate a C/C++ function.

        functionName -- String specifying the name of the function.

        out -- An open file-like object with a write method.  This specifies
        where the generated code is written.

        dataType -- An optional parameter specifying the data type of the input
        data to the function.  Defaults to UINT8.

        crcType -- An optional parameter specifying the data type of the CRC
        value.  Defaults to one of UINT8, UINT16, UINT32, or UINT64 depending
        on the size of the CRC value.
        '''
        if dataType is None:
            dataType = 'UINT8'

        if crcType is None:
            size = 8*self.digest_size
            if size == 24:
                size = 32
            crcType = 'UINT%d' % size

        if self.digest_size == 1:
            # Both 8-bit CRC algorithms are the same
            crcAlgor = 'table[*data ^ (%s)crc]'
        elif self.reverse:
            # The bit reverse algorithms are all the same except for the data
            # type of the crc variable which is specified elsewhere.
            crcAlgor = 'table[*data ^ (%s)crc] ^ (crc >> 8)'
        else:
            # The forward CRC algorithms larger than 8 bits have an extra shift
            # operation to get the high byte.
            shift = 8*(self.digest_size - 1)
            crcAlgor = 'table[*data ^ (%%s)(crc >> %d)] ^ (crc << 8)' % shift

        fmt = '0x%%0%dX' % (2*self.digest_size)
        if self.digest_size <= 4:
            fmt = fmt + 'U,'
        else:
            # Need the long long type identifier to keep gcc from complaining.
            fmt = fmt + 'ULL,'

        # Select the number of entries per row in the output code.
        n = {1:8, 2:8, 3:4, 4:4, 8:2}[self.digest_size]

        lst = []
        for i, val in enumerate(self.table):
            if (i % n) == 0:
                lst.append('\n    ')
            lst.append(fmt % val)

        poly = 'polynomial: 0x%X' % self.poly
        if self.reverse:
            poly = poly + ', bit reverse algorithm'

        if self.xorOut:
            # Need to remove the comma from the format.
            preCondition = '\n    crc = crc ^ %s;' % (fmt[:-1] % self.xorOut)
            postCondition = preCondition
        else:
            preCondition = ''
            postCondition = ''

        if self.digest_size == 3:
            # The 24-bit CRC needs to be conditioned so that only 24-bits are
            # used from the 32-bit variable.
            if self.reverse:
                preCondition += '\n    crc = crc & 0xFFFFFFU;'
            else:
                postCondition += '\n    crc = crc & 0xFFFFFFU;'
                

        parms = {
            'dataType' : dataType,
            'crcType' : crcType,
            'name' : functionName,
            'crcAlgor' : crcAlgor % dataType,
            'crcTable' : ''.join(lst),
            'poly' : poly,
            'preCondition' : preCondition,
            'postCondition' : postCondition,
        }
        out.write(_codeTemplate % parms) 

def _verifyPoly(poly):
    """
    Check the polynomial to make sure that it is acceptable and return the number
    of bits in the CRC.
    """

    msg = 'The degree of the polynomial must be 8, 16, 24, 32 or 64'
    for n in (8,16,24,32,64):
        low = 1<<n
        high = low*2
        if low <= poly < high:
            return n
    raise ValueError(msg)



def _bitrev(x, n):
    """
    Bit reverse the input value.
    """
    y = 0
    for _ in range(n):
        y = (y << 1) | (x & 1)
        x = x >> 1

    return y

#-----------------------------------------------------------------------------
# The following functions compute the CRC for a single byte.  These are used
# to build up the tables needed in the CRC algorithm.  Assumes the high order
# bit of the polynomial has been stripped off.


def _bytecrc(crc, poly, n):
    mask = 1<<(n-1)
    for i in range(8):
        if crc & mask:
            crc = (crc << 1) ^ poly
        else:
            crc = crc << 1
    mask = (1<<n) - 1
    crc = crc & mask

    return crc

def _bytecrc_r(crc, poly, n):
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ poly
        else:
            crc = crc >> 1

    mask = (1<<n) - 1
    crc = crc & mask

    return crc

#-----------------------------------------------------------------------------
# The following functions compute the table needed to compute the CRC.  The
# table is returned as a list.  Note that the array module does not support
# 64-bit integers on a 32-bit architecture as of Python 2.3.
#
# These routines assume that the polynomial and the number of bits in the CRC
# have been checked for validity by the caller.

def _mkTable(poly, n):
    mask = (1<<n) - 1
    poly = poly & mask
    table = [_bytecrc(i<<(n-8),poly,n) for i in range(256)]
    return table

def _mkTable_r(poly, n):
    mask = (1<<n) - 1
    poly = _bitrev(poly & mask, n)
    table = [_bytecrc_r(i,poly,n) for i in range(256)]
    return table


def _crc16r(data, crc, table):
    crc = crc & 0xFFFF

    for x in data:
        crc = table[x ^ (crc & 0xFF)] ^ (crc >> 8)

    return crc

def _crc16(data, crc, table):
    crc = crc & 0xFFFF
    for x in data:
        crc = table[x ^ ((crc>>8) & 0xFF)] ^ ((crc << 8) & 0xFF00)

    return crc

_sizeMap = {
    16 : [_crc16, _crc16r],
}


_sizeToTypeCode = {}

for typeCode in 'B H I L Q'.split():
    size = {1:8, 2:16, 4:32, 8:64}.get(struct.calcsize(typeCode),None)
    if size is not None and size not in _sizeToTypeCode:
        _sizeToTypeCode[size] = '256%s' % typeCode

_sizeToTypeCode[24] = _sizeToTypeCode[32]

# Use Python3 based implementation for CRC and not third-party
_usingExtension = False

def _mkCrcFun(poly, sizeBits, initCrc, rev, xorOut):
    """
    The following function returns a Python function to compute the CRC.

    It must be passed parameters that are already verified & sanitized by
    _verifyParams().

    The returned function calls a low level function that is written in C if the
    extension module could be loaded.  Otherwise, a Python implementation is
    used.

    In addition to this function, a list containing the CRC table is returned.
    """
    if rev:
        tableList = _mkTable_r(poly, sizeBits)
        _fun = _sizeMap[sizeBits][1]
    else:
        tableList = _mkTable(poly, sizeBits)
        _fun = _sizeMap[sizeBits][0]

    _table = tableList
    if _usingExtension:
        _table = struct.pack(_sizeToTypeCode[sizeBits], *tableList)

    if xorOut == 0:
        def crcfun(data, crc=initCrc, table=_table, fun=_fun):
            return fun(data, crc, table)
    else:
        def crcfun(data, crc=initCrc, table=_table, fun=_fun):
            return xorOut ^ fun(data, xorOut ^ crc, table)

    return crcfun, tableList


def _verifyParams(poly, initCrc, xorOut):
    """
    The following function validates the parameters of the CRC, namely,
    poly, and initial/final XOR values.
    It returns the size of the CRC (in bits), and "sanitized" initial/final XOR values.
    """
    sizeBits = _verifyPoly(poly)

    mask = (1<<sizeBits) - 1

    # Adjust the initial CRC to the correct data type (unsigned value).
    initCrc = initCrc & mask

    # Similar for XOR-out value.
    xorOut = xorOut & mask

    return (sizeBits, initCrc, xorOut)

def mkCrcFun(poly, initCrc=~0, rev=True, xorOut=0):
    '''Return a function that computes the CRC using the specified polynomial.

    poly -- integer representation of the generator polynomial
    initCrc -- default initial CRC value
    rev -- when true, indicates that the data is processed bit reversed.
    xorOut -- the final XOR value

    The returned function has the following user interface
    def crcfun(data, crc=initCrc):
    '''

    # First we must verify the params
    (sizeBits, initCrc, xorOut) = _verifyParams(poly, initCrc, xorOut)
    # Make the function (and table), return the function
    return _mkCrcFun(poly, sizeBits, initCrc, rev, xorOut)[0]

def crcDNP(data):
    crc16DNP = mkCrcFun(0x13D65) # 'crc-16-dnp'
    return crc16DNP(data)


def CRC_check(chunk, crc):
    chunk_crc = crcDNP(chunk)
    crc = struct.unpack('<H', crc)[0]
    if crc == chunk_crc:
        return True, crc
    else:
        return False, crc


def update_data_chunk_crc(chunk):
    crc = crcDNP(chunk[:-2])
    chunk = chunk[:-2] + struct.pack('<H', crc)
    return chunk


def add_CRC_payload(payload):
    if len(payload) > 18:
        chunk = payload[:18]
        chunk = update_data_chunk_crc(chunk)
        payload = chunk + payload[18:]

    else:
        chunk = payload[:-2]
        chunk = update_data_chunk_crc(chunk)
        payload = chunk
    return payload


applicationFunctionCode = {
    0: "CONFIRM",
    1: "READ",
    2: "WRITE",
    3: "SELECT",
    4: "OPERATE",
    5: "DIRECT_OPERATE",
    6: "DIRECT_OPERATE_NR",
    7: "IMMED_FREEZE",
    8: "IMMED_FREEZE_NR",
    9: "FREEZE_CLEAR",
    10: "FREEZE_CLEAR_NR",
    11: "FREEZE_AT_TIME",
    12: "FREEZE_AT_TIME_NR",
    13: "COLD_RESTART",
    14: "WARM_RESTART",
    15: "INITIALIZE_DATA",
    16: "INITIALIZE_APPL",
    17: "START_APPL",
    18: "STOP_APPL",
    19: "SAVE_CONFIG",
    20: "ENABLE_UNSOLICITED",
    21: "DISABLE_UNSOLICITED",
    22: "ASSIGN_CLASS",
    23: "DELAY_MEASURE",
    24: "RECORD_CURRENT_TIME",
    25: "OPEN_FILE",
    26: "CLOSE_FILE",
    27: "DELETE_FILE",
    28: "GET_FILE_INFO",
    29: "AUTHENTICATE_FILE",
    30: "ABORT_FILE",
    31: "ACTIVATE_CONFIG",
    32: "AUTHENTICATE_REQ",
    33: "AUTH_REQ_NO_ACK",
    129: "RESPONSE",
    130: "UNSOLICITED_RESPONSE",
    131: "AUTHENTICATE_RESP",
}


class DNP3RequestDataObjects(Packet):
    fields_desc = [
        BitField("Obj", 1, 4),
        BitField("Var", 1, 4),
        BitField("IndexPref", 1, 4),
        BitEnumField("QualfierCode", 1, 4, bitState),
    ]

    def extract_padding(self, s):
        return b"", s

class DNP3Application(Packet):
    def guess_payload_class(self, payload):
        return Packet.guess_payload_class(self, payload)


class DNP3ApplicationControl(Packet):
    fields_desc = [
        BitEnumField("FIN", 1, 1, bitState),
        BitEnumField("FIR", 1, 1, bitState),
        BitEnumField("CON", 1, 1, bitState),
        BitEnumField("UNS", 1, 1, bitState),
        BitField("SEQ", 1, 4),
    ]

    def extract_padding(self, s):
        return b"", s


class DNP3ApplicationIIN(Packet):
    name = "DNP3_Application_response"
    fields_desc = [
        BitEnumField("DEVICE_RESTART", UNSET, 1, bitState),
        BitEnumField("DEVICE_TROUBLE", UNSET, 1, bitState),
        BitEnumField("LOCAL_CONTROL", UNSET, 1, bitState),
        BitEnumField("NEED_TIME", UNSET, 1, bitState),
        BitEnumField("CLASS_3_EVENTS", UNSET, 1, bitState),
        BitEnumField("CLASS_2_EVENTS", UNSET, 1, bitState),
        BitEnumField("CLASS_1_EVENTS", UNSET, 1, bitState),
        BitEnumField("BROADCAST", UNSET, 1, bitState),
        BitEnumField("RESERVED_1", UNSET, 1, bitState),
        BitEnumField("RESERVED_2", UNSET, 1, bitState),
        BitEnumField("CONFIG_CORRUPT", UNSET, 1, bitState),
        BitEnumField("ALREADY_EXECUTING", UNSET, 1, bitState),
        BitEnumField("EVENT_BUFFER_OVERFLOW", UNSET, 1, bitState),
        BitEnumField("PARAMETER_ERROR", UNSET, 1, bitState),
        BitEnumField("OBJECT_UNKNOWN", UNSET, 1, bitState),
        BitEnumField("NO_FUNC_CODE_SUPPORT", UNSET, 1, bitState),
    ]

    def extract_padding(self, s):
        return b"", s

class DNP3ApplicationResponse(DNP3Application):
    name = "DNP3_Application_response"
    fields_desc = [
        PacketField("Application_control", DNP3ApplicationControl(), DNP3ApplicationControl),
        BitEnumField("FUNC_CODE", 1, 8, applicationFunctionCode),
        PacketField("IIN", DNP3ApplicationIIN(), DNP3ApplicationIIN),
    ]

    def mysummary(self):
        if self.underlayer is not None and isinstance(self.underlayer.underlayer, DNP3):
            print(self.FUNC_CODE.SEQ, "Hello")
            return self.underlayer.underlayer.sprintf(
                DNP3_summary + Transport_summary + Application_Rsp_summary
            )
        if isinstance(self.underlayer, DNP3Transport):
            return self.underlayer.sprintf(Transport_summary + Application_Rsp_summary)
        else:
            return self.sprintf(Application_Req_summary)

class DNP3ApplicationRequest(DNP3Application):
    name = "DNP3_Application_request"
    fields_desc = [
        PacketField("Application_control", DNP3ApplicationControl(), DNP3ApplicationControl),
        BitEnumField("FUNC_CODE", 1, 8, applicationFunctionCode),
    ]

    def mysummary(self):
        if self.underlayer is not None and isinstance(self.underlayer.underlayer, DNP3):
            return self.underlayer.underlayer.sprintf(
                DNP3_summary + Transport_summary + Application_Req_summary
            )
        if isinstance(self.underlayer, DNP3Transport):
            return self.underlayer.sprintf(Transport_summary + Application_Req_summary)
        else:
            return self.sprintf(Application_Req_summary)


class DNP3Transport(Packet):
    name = "DNP3_Transport"
    fields_desc = [
        BitEnumField("FIN", None, 1, bitState),
        BitEnumField("FIR", None, 1, bitState),
        BitField("SEQUENCE", None, 6),
    ]

    def guess_payload_class(self, payload):
        if isinstance(self.underlayer, DNP3):
            DIR = self.underlayer.CONTROL.DIR

            if DIR == MASTER:
                return DNP3ApplicationRequest

            if DIR == OUTSTATION:
                return DNP3ApplicationResponse

        return Packet.guess_payload_class(self, payload)


class DNP3HeaderControl(Packet):
    name = "DNP3_Header_control"

    controlFunctionCodePri = {
        0: "RESET_LINK_STATES",
        2: "TEST_LINK_STATES",
        3: "CONFIRMED_USER_DATA",
        4: "UNCONFIRMED_USER_DATA",
        9: "REQUEST_LINK_STATUS",
    }

    controlFunctionCodeSec = {
        0: "ACK",
        1: "NACK",
        11: "LINK_STATUS",
        15: "NOT_SUPPORTED",
    }

    cond_field = [
        BitEnumField("FCB", 0, 1, bitState),
        BitEnumField("FCV", 0, 1, bitState),
        BitEnumField("FUNC_CODE_PRI", 4, 4,  controlFunctionCodePri),
        BitEnumField("reserved", 0, 1, bitState),
        BitEnumField("DFC", 0, 1, bitState),
        BitEnumField("FUNC_CODE_SEC", 4, 4,  controlFunctionCodeSec),
    ]

    fields_desc = [
        BitEnumField("DIR", MASTER, 1, stations),  # 9.2.4.1.3.1 DIR bit field
        BitEnumField("PRM", MASTER, 1,  stations),  # 9.2.4.1.3.2 PRM bit field
        ConditionalField(cond_field[0], lambda x:x.PRM == MASTER),
        ConditionalField(cond_field[1], lambda x:x.PRM == MASTER),
        ConditionalField(cond_field[2], lambda x:x.PRM == MASTER),
        ConditionalField(cond_field[3], lambda x:x.PRM == OUTSTATION),
        ConditionalField(cond_field[4], lambda x:x.PRM == OUTSTATION),
        ConditionalField(cond_field[5], lambda x:x.PRM == OUTSTATION),
    ]

    def extract_padding(self, s):
        return b"", s


class DNP3(Packet):
    name = "DNP3"
    fields_desc = [
        XShortField("START", 0x0564),
        ByteField("LENGTH", None),
        PacketField("CONTROL", None, DNP3HeaderControl),
        LEShortField("DESTINATION", None),
        LEShortField("SOURCE", None),
        XShortField("CRC", None),
    ]

    data_chunks = []  # Data Chunks are 16 octets
    data_chunks_crc = []
    chunk_len = 18
    data_chunk_len = 16

    def show_data_chunks(self):
        for i, data_chunk in enumerate(self.data_chunks):
            print(f"\tData Chunk {i}, Len {len(data_chunk)}, "
                  "CRC (", hex(struct.unpack('<H', self.data_chunks_crc[i])[0]), ")")


    def add_data_chunk(self, chunk):
        chunk = update_data_chunk_crc(chunk)
        self.data_chunks.append(chunk[:-2])
        self.data_chunks_crc.append(chunk[-2:])

    def post_build(self, pkt, pay):
        cnk_len = self.chunk_len
        pay_len = len(pay)
        # pkt_len = len(pkt)
        # total = pkt_len + pay_len
        chunks = int(pay_len / cnk_len)  # chunk size
        # chunks = total / cnk_len  # chunk size
        last_chunk = pay_len % cnk_len

        if last_chunk > 0:
            chunks += 1

        if pay_len == 3 and self.CONTROL.DIR == MASTER:
            # No IIN in Application layer and empty Payload
            pay = pay + struct.pack('H', crcDNP(pay))

        if pay_len == 5 and self.CONTROL.DIR == OUTSTATION:
            # IIN in Application layer and empty Payload
            pay = pay + struct.pack('H', crcDNP(pay))

        if self.LENGTH is None:
             # Remove length , crc, start octets as part of length
            length = len(pkt+pay) - ((chunks * 2) + 1 + 2 + 2)
            pkt = pkt[:2] + struct.pack('<B', length) + pkt[3:]

        CRC = crcDNP(pkt[:8])  # use only the first 8 octets

        if self.CRC is None:
            pkt = pkt[:-2] + struct.pack('H', CRC)

        else:
            if CRC != self.CRC:
                pkt = pkt[:-2] + struct.pack('H', CRC)

        self.data_chunks = []
        self.data_chunks_crc = []

        remaining_pay = pay_len
        for c in range(chunks):
            index = c * cnk_len  # data chunk

            if (remaining_pay < cnk_len) and (remaining_pay > 0):
                self.add_data_chunk(pay[index:])
                break  # should be the last chunk
            else:
                self.add_data_chunk(pay[index:index + cnk_len])
                remaining_pay -= cnk_len

        payload = b''
        for chunk, data_chunk in enumerate(self.data_chunks):
            payload = payload + data_chunk + self.data_chunks_crc[chunk]
        #  self.show_data_chunks()  # --DEBUGGING
        return pkt+payload

    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return DNP3Transport
        else:
            return Packet.guess_payload_class(self, payload)


bind_layers(TCP, DNP3, dport=dnp3_port)
bind_layers(TCP, DNP3, sport=dnp3_port)
bind_layers(UDP, DNP3, dport=dnp3_port)
bind_layers(UDP, DNP3, sport=dnp3_port)
