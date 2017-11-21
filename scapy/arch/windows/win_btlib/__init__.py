## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## This program is published under a GPLv2 license

# Original source: PyBluez project. Modified

# Last Updated: 18/11/2017
# The library is located in the x86 or x64 folder, depending of the architecture
# Source code can be found in pybtscapy_lib_source.zip

import sys, os, platform
_pybtscapy_path = os.path.dirname(os.path.abspath(__file__))
# Select architecture
if "64" in platform.architecture()[0]:
    _pybtscapy_path = os.path.join(_pybtscapy_path, "x64")
else:
    _pybtscapy_path = os.path.join(_pybtscapy_path, "x86")
sys.path.append(_pybtscapy_path)

import PyBTScapy as bt

L2CAP=0
RFCOMM=3

PORT_ANY=0

# Service Class IDs
SDP_SERVER_CLASS = "1000"
BROWSE_GRP_DESC_CLASS = "1001"
PUBLIC_BROWSE_GROUP = "1002"
SERIAL_PORT_CLASS = "1101"
LAN_ACCESS_CLASS = "1102"
DIALUP_NET_CLASS = "1103"
IRMC_SYNC_CLASS = "1104"
OBEX_OBJPUSH_CLASS = "1105"
OBEX_FILETRANS_CLASS = "1106"
IRMC_SYNC_CMD_CLASS = "1107"
HEADSET_CLASS = "1108"
CORDLESS_TELEPHONY_CLASS = "1109"
AUDIO_SOURCE_CLASS = "110a"
AUDIO_SINK_CLASS = "110b"
AV_REMOTE_TARGET_CLASS = "110c"
ADVANCED_AUDIO_CLASS = "110d"
AV_REMOTE_CLASS = "110e"
VIDEO_CONF_CLASS = "110f"
INTERCOM_CLASS = "1110"
FAX_CLASS = "1111"
HEADSET_AGW_CLASS = "1112"
WAP_CLASS = "1113"
WAP_CLIENT_CLASS = "1114"
PANU_CLASS = "1115"
NAP_CLASS = "1116"
GN_CLASS = "1117"
DIRECT_PRINTING_CLASS = "1118"
REFERENCE_PRINTING_CLASS = "1119"
IMAGING_CLASS = "111a"
IMAGING_RESPONDER_CLASS = "111b"
IMAGING_ARCHIVE_CLASS = "111c"
IMAGING_REFOBJS_CLASS = "111d"
HANDSFREE_CLASS = "111e"
HANDSFREE_AGW_CLASS = "111f"
DIRECT_PRT_REFOBJS_CLASS = "1120"
REFLECTED_UI_CLASS = "1121"
BASIC_PRINTING_CLASS = "1122"
PRINTING_STATUS_CLASS = "1123"
HID_CLASS = "1124"
HCR_CLASS = "1125"
HCR_PRINT_CLASS = "1126"
HCR_SCAN_CLASS = "1127"
CIP_CLASS = "1128"
VIDEO_CONF_GW_CLASS = "1129"
UDI_MT_CLASS = "112a"
UDI_TA_CLASS = "112b"
AV_CLASS = "112c"
SAP_CLASS = "112d"
PNP_INFO_CLASS = "1200"
GENERIC_NETWORKING_CLASS = "1201"
GENERIC_FILETRANS_CLASS = "1202"
GENERIC_AUDIO_CLASS = "1203"
GENERIC_TELEPHONY_CLASS = "1204"
UPNP_CLASS = "1205"
UPNP_IP_CLASS = "1206"
UPNP_PAN_CLASS = "1300"
UPNP_LAP_CLASS = "1301"
UPNP_L2CAP_CLASS = "1302"
VIDEO_SOURCE_CLASS = "1303"
VIDEO_SINK_CLASS = "1304"

# Bluetooth Profile Descriptors
SDP_SERVER_PROFILE = ( SDP_SERVER_CLASS, 0x0100)
BROWSE_GRP_DESC_PROFILE = ( BROWSE_GRP_DESC_CLASS, 0x0100)
SERIAL_PORT_PROFILE = ( SERIAL_PORT_CLASS, 0x0100)
LAN_ACCESS_PROFILE = ( LAN_ACCESS_CLASS, 0x0100)
DIALUP_NET_PROFILE = ( DIALUP_NET_CLASS, 0x0100)
IRMC_SYNC_PROFILE = ( IRMC_SYNC_CLASS, 0x0100)
OBEX_OBJPUSH_PROFILE = ( OBEX_OBJPUSH_CLASS, 0x0100)
OBEX_FILETRANS_PROFILE = ( OBEX_FILETRANS_CLASS, 0x0100)
IRMC_SYNC_CMD_PROFILE = ( IRMC_SYNC_CMD_CLASS, 0x0100)
HEADSET_PROFILE = ( HEADSET_CLASS, 0x0100)
CORDLESS_TELEPHONY_PROFILE = ( CORDLESS_TELEPHONY_CLASS, 0x0100)
AUDIO_SOURCE_PROFILE = ( AUDIO_SOURCE_CLASS, 0x0100)
AUDIO_SINK_PROFILE = ( AUDIO_SINK_CLASS, 0x0100)
AV_REMOTE_TARGET_PROFILE = ( AV_REMOTE_TARGET_CLASS, 0x0100)
ADVANCED_AUDIO_PROFILE = ( ADVANCED_AUDIO_CLASS, 0x0100)
AV_REMOTE_PROFILE = ( AV_REMOTE_CLASS, 0x0100)
VIDEO_CONF_PROFILE = ( VIDEO_CONF_CLASS, 0x0100)
INTERCOM_PROFILE = ( INTERCOM_CLASS, 0x0100)
FAX_PROFILE = ( FAX_CLASS, 0x0100)
HEADSET_AGW_PROFILE = ( HEADSET_AGW_CLASS, 0x0100)
WAP_PROFILE = ( WAP_CLASS, 0x0100)
WAP_CLIENT_PROFILE = ( WAP_CLIENT_CLASS, 0x0100)
PANU_PROFILE = ( PANU_CLASS, 0x0100)
NAP_PROFILE = ( NAP_CLASS, 0x0100)
GN_PROFILE = ( GN_CLASS, 0x0100)
DIRECT_PRINTING_PROFILE = ( DIRECT_PRINTING_CLASS, 0x0100)
REFERENCE_PRINTING_PROFILE = ( REFERENCE_PRINTING_CLASS, 0x0100)
IMAGING_PROFILE = ( IMAGING_CLASS, 0x0100)
IMAGING_RESPONDER_PROFILE = ( IMAGING_RESPONDER_CLASS, 0x0100)
IMAGING_ARCHIVE_PROFILE = ( IMAGING_ARCHIVE_CLASS, 0x0100)
IMAGING_REFOBJS_PROFILE = ( IMAGING_REFOBJS_CLASS, 0x0100)
HANDSFREE_PROFILE = ( HANDSFREE_CLASS, 0x0100)
HANDSFREE_AGW_PROFILE = ( HANDSFREE_AGW_CLASS, 0x0100)
DIRECT_PRT_REFOBJS_PROFILE = ( DIRECT_PRT_REFOBJS_CLASS, 0x0100)
REFLECTED_UI_PROFILE = ( REFLECTED_UI_CLASS, 0x0100)
BASIC_PRINTING_PROFILE = ( BASIC_PRINTING_CLASS, 0x0100)
PRINTING_STATUS_PROFILE = ( PRINTING_STATUS_CLASS, 0x0100)
HID_PROFILE = ( HID_CLASS, 0x0100)
HCR_PROFILE = ( HCR_SCAN_CLASS, 0x0100)
HCR_PRINT_PROFILE = ( HCR_PRINT_CLASS, 0x0100)
HCR_SCAN_PROFILE = ( HCR_SCAN_CLASS, 0x0100)
CIP_PROFILE = ( CIP_CLASS, 0x0100)
VIDEO_CONF_GW_PROFILE = ( VIDEO_CONF_GW_CLASS, 0x0100)
UDI_MT_PROFILE = ( UDI_MT_CLASS, 0x0100)
UDI_TA_PROFILE = ( UDI_TA_CLASS, 0x0100)
AV_PROFILE = ( AV_CLASS, 0x0100)
SAP_PROFILE = ( SAP_CLASS, 0x0100)
PNP_INFO_PROFILE = ( PNP_INFO_CLASS, 0x0100)
GENERIC_NETWORKING_PROFILE = ( GENERIC_NETWORKING_CLASS, 0x0100)
GENERIC_FILETRANS_PROFILE = ( GENERIC_FILETRANS_CLASS, 0x0100)
GENERIC_AUDIO_PROFILE = ( GENERIC_AUDIO_CLASS, 0x0100)
GENERIC_TELEPHONY_PROFILE = ( GENERIC_TELEPHONY_CLASS, 0x0100)
UPNP_PROFILE = ( UPNP_CLASS, 0x0100)
UPNP_IP_PROFILE = ( UPNP_IP_CLASS, 0x0100)
UPNP_PAN_PROFILE = ( UPNP_PAN_CLASS, 0x0100)
UPNP_LAP_PROFILE = ( UPNP_LAP_CLASS, 0x0100)
UPNP_L2CAP_PROFILE = ( UPNP_L2CAP_CLASS, 0x0100)
VIDEO_SOURCE_PROFILE = ( VIDEO_SOURCE_CLASS, 0x0100)
VIDEO_SINK_PROFILE = ( VIDEO_SINK_CLASS, 0x0100)

# Universal Service Attribute IDs
SERVICE_RECORD_HANDLE_ATTRID = 0x0000
SERVICE_CLASS_ID_LIST_ATTRID = 0x0001
SERVICE_RECORD_STATE_ATTRID = 0x0002
SERVICE_ID_ATTRID = 0x0003
PROTOCOL_DESCRIPTOR_LIST_ATTRID = 0x0004
BROWSE_GROUP_LIST_ATTRID = 0x0005
LANGUAGE_BASE_ATTRID_LIST_ATTRID = 0x0006
SERVICE_INFO_TIME_TO_LIVE_ATTRID = 0x0007
SERVICE_AVAILABILITY_ATTRID = 0x0008
BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRID = 0x0009
DOCUMENTATION_URL_ATTRID = 0x000a
CLIENT_EXECUTABLE_URL_ATTRID = 0x000b
ICON_URL_ATTRID = 0x000c
SERVICE_NAME_ATTRID = 0x0100
SERVICE_DESCRIPTION_ATTRID = 0x0101
PROVIDER_NAME_ATTRID = 0x0102

# Protocol UUIDs
SDP_UUID       = "0001"
UDP_UUID       = "0002"
RFCOMM_UUID    = "0003"
TCP_UUID       = "0004"
TCS_BIN_UUID   = "0005"
TCS_AT_UUID    = "0006"
OBEX_UUID      = "0008"
IP_UUID        = "0009"
FTP_UUID       = "000a"
HTTP_UUID      = "000c"
WSP_UUID       = "000e"
BNEP_UUID      = "000f"
UPNP_UUID      = "0010"
HIDP_UUID      = "0011"
HCRP_CTRL_UUID = "0012"
HCRP_DATA_UUID = "0014"
HCRP_NOTE_UUID = "0016"
AVCTP_UUID     = "0017"
AVDTP_UUID     = "0019"
CMTP_UUID      = "001b"
UDI_UUID       = "001d"
L2CAP_UUID     = "0100"

class BluetoothError (IOError):
    pass

def is_valid_address (s):
    """
    returns True if address is a valid Bluetooth address
    valid address are always strings of the form XX:XX:XX:XX:XX:XX
    where X is a hexadecimal character.  For example,
        01:23:45:67:89:AB is a valid address, but
        IN:VA:LI:DA:DD:RE is not
    """
    try:
        pairs = s.split (":")
        if len (pairs) != 6: return False
        for b in pairs: int (b, 16)
    except:
        return False
    return True

def is_valid_uuid (uuid):
    """
    is_valid_uuid (uuid) -> bool
    returns True if uuid is a valid 128-bit UUID.
    valid UUIDs are always strings taking one of the following forms:
        XXXX
        XXXXXXXX
        XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    where each X is a hexadecimal digit (case insensitive)
    """
    try:
        if len (uuid) == 4:
            if int (uuid, 16) < 0: return False
        elif len (uuid) == 8:
            if int (uuid, 16) < 0: return False
        elif len (uuid) == 36:
            pieces = uuid.split ("-")
            if len (pieces) != 5 or \
                    len (pieces[0]) != 8 or \
                    len (pieces[1]) != 4 or \
                    len (pieces[2]) != 4 or \
                    len (pieces[3]) != 4 or \
                    len (pieces[4]) != 12:
                return False
            [ int (p, 16) for p in pieces ]
        else:
            return False
    except ValueError: 
        return False
    except TypeError:
        return False
    return True

def to_full_uuid (uuid):
    """
    converts a short 16-bit or 32-bit reserved UUID to a full 128-bit Bluetooth
    UUID.
    """
    if not is_valid_uuid (uuid): raise ValueError ("invalid UUID")
    if len (uuid) == 4:
        return "0000%s-0000-1000-8000-00805F9B34FB" % uuid
    elif len (uuid) == 8:
        return "%s-0000-1000-8000-00805F9B34FB" % uuid
    else:
        return uuid

# =============== parsing and constructing raw SDP records ============

def sdp_parse_size_desc (data):
    dts = struct.unpack ("B", data[0:1])[0]
    dtype, dsizedesc = dts >> 3, dts & 0x7
    dstart = 1
    if   dtype == 0:     dsize = 0
    elif dsizedesc == 0: dsize = 1
    elif dsizedesc == 1: dsize = 2
    elif dsizedesc == 2: dsize = 4
    elif dsizedesc == 3: dsize = 8
    elif dsizedesc == 4: dsize = 16
    elif dsizedesc == 5:
        dsize = struct.unpack ("B", data[1:2])[0]
        dstart += 1
    elif dsizedesc == 6:
        dsize = struct.unpack ("!H", data[1:3])[0]
        dstart += 2
    elif dsizedesc == 7:
        dsize == struct.unpack ("!I", data[1:5])[0]
        dstart += 4

    if dtype > 8:
        raise ValueError ("Invalid TypeSizeDescriptor byte %s %d, %d" \
                % (binascii.hexlify (data[0:1]), dtype, dsizedesc))

    return dtype, dsize, dstart

def sdp_parse_uuid (data, size):
    if size == 2:
        return binascii.hexlify (data)
    elif size == 4:
        return binascii.hexlify (data)
    elif size == 16:
        return "%08X-%04X-%04X-%04X-%04X%08X" % struct.unpack ("!IHHHHI", data)
    else: return ValueError ("invalid UUID size")

def sdp_parse_int (data, size, signed):
    fmts = { 1 : "!b" , 2 : "!h" , 4 : "!i" , 8 : "!q" , 16 : "!qq" }
    fmt = fmts[size]
    if not signed: fmt = fmt.upper ()
    if fmt in [ "!qq", "!QQ" ]:
        upp, low = struct.unpack ("!QQ", data)
        result = ( upp << 64) | low
        if signed:
            result=- ((~ (result-1))&0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        return result
    else:
        return struct.unpack (fmt, data)[0]

def sdp_parse_data_elementSequence (data):
    result = []
    pos = 0
    datalen = len (data)
    while pos < datalen:
        rtype, rval, consumed = sdp_parse_data_element (data[pos:])
        pos += consumed
        result.append ( (rtype, rval))
    return result

def sdp_parse_data_element (data):
    dtype, dsize, dstart = sdp_parse_size_desc (data)
    elem = data[dstart:dstart+dsize]

    if dtype == 0:
        rtype, rval = "Nil", None
    elif dtype == 1:
        rtype, rval = "UInt%d"% (dsize*8), sdp_parse_int (elem, dsize, False)
    elif dtype == 2:
        rtype, rval = "SInt%d"% (dsize*8), sdp_parse_int (elem, dsize, True)
    elif dtype == 3:
        rtype, rval = "UUID", sdp_parse_uuid (elem, dsize)
    elif dtype == 4:
        rtype, rval = "String", elem
    elif dtype == 5:
        rtype, rval = "Bool", (struct.unpack ("B", elem)[0] != 0)
    elif dtype == 6:
        rtype, rval = "ElemSeq", sdp_parse_data_elementSequence (elem)
    elif dtype == 7:
        rtype, rval = "AltElemSeq", sdp_parse_data_elementSequence (elem)
    elif dtype == 8:
        rtype, rval = "URL", elem

    return rtype, rval, dstart+dsize

def sdp_parse_raw_record (data):
    dtype, dsize, dstart = sdp_parse_size_desc (data)
    assert dtype == 6

    pos = dstart
    datalen = len (data)
    record = {}
    while pos < datalen:
        type, attrid, consumed = sdp_parse_data_element (data[pos:])
        assert type == "UInt16"
        pos += consumed
        type, attrval, consumed = sdp_parse_data_element (data[pos:])
        pos += consumed
        record[attrid] = attrval
    return record

def sdp_make_data_element (type, value):
    def maketsd (tdesc, sdesc):
        return struct.pack ("B", (tdesc << 3) | sdesc)
    def maketsdl (tdesc, size):
        if   size < (1<<8):  return struct.pack ("!BB", tdesc << 3 | 5, size)
        elif size < (1<<16): return struct.pack ("!BH", tdesc << 3 | 6, size)
        else:                return struct.pack ("!BI", tdesc << 3 | 7, size)

    easyinttypes = { "UInt8"   : (1, 0, "!B"),  "UInt16"  : (1, 1, "!H"),
                     "UInt32"  : (1, 2, "!I"),  "UInt64"  : (1, 3, "!Q"),
                     "SInt8"   : (2, 0, "!b"),  "SInt16"  : (2, 1, "!h"),
                     "SInt32"  : (2, 2, "!i"),  "SInt64"  : (2, 3, "!q"),
                     }

    if type == "Nil": 
        return maketsd (0, 0)
    elif type in easyinttypes:
        tdesc, sdesc, fmt = easyinttypes[type]
        return maketsd (tdesc, sdesc) + struct.pack (fmt, value)
    elif type == "UInt128":
        ts = maketsd (1, 4)
        upper = ts >> 64
        lower = (ts & 0xFFFFFFFFFFFFFFFF)
        return ts + struct.pack ("!QQ", upper, lower)
    elif type == "SInt128":
        ts = maketsd (2, 4)
        # FIXME
        raise NotImplementedException ("128-bit signed int NYI!")
    elif type == "UUID":
        if len (value) == 4:
            return maketsd (3, 1) + binascii.unhexlify (value)
        elif len (value) == 8:
            return maketsd (3, 2) + binascii.unhexlify (value)
        elif len (value) == 36:
            return maketsd (3, 4) + binascii.unhexlify (value.replace ("-",""))
    elif type == "String":
        return maketsdl (4, len (value)) + str.encode(value)
    elif type == "Bool":
        return maketsd (5,0) + (value and "\x01" or "\x00")
    elif type == "ElemSeq":
        packedseq = bytes()
        for subtype, subval in value:
            nextelem = sdp_make_data_element (subtype, subval)
            packedseq = packedseq + nextelem
        return maketsdl (6, len (packedseq)) + packedseq
    elif type == "AltElemSeq":
        packedseq = bytes()
        for subtype, subval in value:
            packedseq = packedseq + sdp_make_data_element (subtype, subval)
        return maketsdl (7, len (packedseq)) + packedseq
    elif type == "URL":
        return maketsdl (8, len (value)) + value
    else:
        raise ValueError ("invalid type %s" % type)

### INIT WINSOCKET SERVICE ###

bt.initwinsock()

# ============== SDP service registration and unregistration ============

def discover_devices (duration=8, flush_cache=True, lookup_names=False,
                      lookup_class=False, device_id=-1):
    """Returns list of bluetooth devices."""
    #this is order of items in C-code
    btAddresIndex = 0
    namesIndex = 1
    classIndex = 2

    devices = bt.discover_devices(duration=duration, flush_cache=flush_cache)
    ret = list()
    for device in devices:
        item = [device[btAddresIndex],]
        if lookup_names:
            item.append(device[namesIndex])
        if lookup_class:
            item.append(device[classIndex])

        if len(item) == 1: # in case of address-only we return string not tuple
            ret.append(item[0])
        else:
            ret.append(tuple(i for i in item))
    return ret


def read_local_bdaddr():
    return bt.list_local()


def lookup_name (address, timeout=10):
    if not is_valid_address (address): 
        raise ValueError ("Invalid Bluetooth address")
    return bt.lookup_name (address)


class _WinBluetoothSocket:
    def __init__ (self, proto = RFCOMM, sockfd = None):
        if proto not in [ RFCOMM ]:
            raise ValueError ("invalid protocol")

        if sockfd:
            self._sockfd = sockfd
        else:
            self._sockfd = bt.socket (bt.SOCK_STREAM, bt.BTHPROTO_RFCOMM)
        self._proto = proto

        # used by advertise_service and stop_advertising
        self._sdp_handle = None
        self._raw_sdp_record = None

        # used to track if in blocking or non-blocking mode (FIONBIO appears
        # write only)
        self._blocking = True
        self._timeout = False

    def bind (self, addrport):
        if self._proto == RFCOMM:
            addr, port = addrport

            if port == 0: port = bt.BT_PORT_ANY
            bt.bind (self._sockfd, addr, port)

    def listen (self, backlog):
        bt.listen (self._sockfd, backlog)

    def _accept (self):
        clientfd, addr, port = bt.accept (self._sockfd)
        client = (self._proto, clientfd)
        return client, (addr, port)

    def connect (self, addrport):
        addr, port = addrport
        bt.connect (self._sockfd, addr, port)

    def _send (self, data):
        return bt.send (self._sockfd, data)

    def _recv (self, numbytes):
        return bt.recv (self._sockfd, numbytes)

    def _close (self):
        return bt.close (self._sockfd)

    def getsockname (self):
        return bt.getsockname (self._sockfd)

    def setblocking (self, blocking):
        bt.setblocking (self._sockfd, blocking)
        self._blocking = blocking

    def settimeout (self, timeout):
        if timeout < 0: raise ValueError ("invalid timeout")

        if timeout == 0:
            self.setblocking (False)
        else:
            self.setblocking (True)

        bt.settimeout (self._sockfd, timeout)
        self._timeout = timeout

    def gettimeout (self):    
        if self._blocking and not self._timeout: return None
        return bt.gettimeout (self._sockfd)

    def fileno (self):
        return self._sockfd

    def dup (self):
        return _WinBluetoothSocket (self._proto, sockfd=bt.dup (self._sockfd))

    def makefile (self):
        # TODO
        raise Exception("Not yet implemented")


def advertise_service (sock, name, service_id = "", service_classes = [], \
        profiles = [], provider = "", description = "", protocols = []):
    if service_id != "" and not is_valid_uuid (service_id):
        raise ValueError ("invalid UUID specified for service_id")
    for uuid in service_classes:
        if not is_valid_uuid (uuid):
            raise ValueError ("invalid UUID specified in service_classes")
    for uuid, version in profiles:
        if not is_valid_uuid (uuid) or  version < 0 or  version > 0xFFFF:
            raise ValueError ("Invalid Profile Descriptor")
    for uuid in protocols:
        if not is_valid_uuid (uuid):
            raise ValueError ("invalid UUID specified in protocols")        

    if sock._raw_sdp_record is not None:
        raise IOError ("service already advertised")

    avpairs = []

    # service UUID
    if len (service_id) > 0:
        avpairs.append (("UInt16", SERVICE_ID_ATTRID))
        avpairs.append (("UUID", service_id))

    # service class list
    if len (service_classes) > 0:
        seq = [ ("UUID", svc_class) for svc_class in service_classes ]
        avpairs.append (("UInt16", SERVICE_CLASS_ID_LIST_ATTRID))
        avpairs.append (("ElemSeq", seq))

    # set protocol and port information
    assert sock._proto == RFCOMM
    addr, port = sock.getsockname ()
    avpairs.append (("UInt16", PROTOCOL_DESCRIPTOR_LIST_ATTRID))
    l2cap_pd = ("ElemSeq", (("UUID", L2CAP_UUID),))
    rfcomm_pd = ("ElemSeq", (("UUID", RFCOMM_UUID), ("UInt8", port)))
    proto_list = [ l2cap_pd, rfcomm_pd ]
    for proto_uuid in protocols:
        proto_list.append (("ElemSeq", (("UUID", proto_uuid),)))
    avpairs.append (("ElemSeq", proto_list))

    # make the service publicly browseable
    avpairs.append (("UInt16", BROWSE_GROUP_LIST_ATTRID))
    avpairs.append (("ElemSeq", (("UUID", PUBLIC_BROWSE_GROUP),)))

    # profile descriptor list
    if len (profiles) > 0:
        seq = [ ("ElemSeq", (("UUID",uuid), ("UInt16",version))) \
                for uuid, version in profiles ]
        avpairs.append (("UInt16", 
            BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRID))
        avpairs.append (("ElemSeq", seq))

    # service name
    avpairs.append (("UInt16", SERVICE_NAME_ATTRID))
    avpairs.append (("String", name))

    # service description
    if len (description) > 0:
        avpairs.append (("UInt16", SERVICE_DESCRIPTION_ATTRID))
        avpairs.append (("String", description))
    
    # service provider
    if len (provider) > 0:
        avpairs.append (("UInt16", PROVIDER_NAME_ATTRID))
        avpairs.append (("String", provider))

    sock._raw_sdp_record = sdp_make_data_element ("ElemSeq", avpairs)
#    pr = sdp_parse_raw_record (sock._raw_sdp_record)
#    for attrid, val in pr.items ():
#        print "%5s: %s" % (attrid, val)
#    print binascii.hexlify (sock._raw_sdp_record)
#    print repr (sock._raw_sdp_record)

    sock._sdp_handle = bt.set_service_raw (sock._raw_sdp_record, True)

def stop_advertising (sock):
    if sock._raw_sdp_record is None:
        raise IOError ("service isn't advertised, " \
                        "but trying to un-advertise")
    bt.set_service_raw (sock._raw_sdp_record, False, sock._sdp_handle)
    sock._raw_sdp_record = None
    sock._sdp_handle = None

def find_service (name = None, uuid = None, address = None):
    if address is not None:
        addresses = [ address ]
    else:
        addresses = discover_devices (lookup_names = False)

    results = []

    for addr in addresses:
        uuidstr = uuid or PUBLIC_BROWSE_GROUP
        if not is_valid_uuid (uuidstr): raise ValueError ("invalid UUID")

        uuidstr = to_full_uuid (uuidstr)

        dresults = bt.find_service (addr, uuidstr)

        for dict in dresults:
            raw = dict["rawrecord"]

            record = sdp_parse_raw_record (raw)

            if SERVICE_CLASS_ID_LIST_ATTRID in record:
                svc_class_id_list = [ t[1] for t in \
                        record[SERVICE_CLASS_ID_LIST_ATTRID] ]
                dict["service-classes"] = svc_class_id_list
            else:
                dict["services-classes"] = []

            if BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRID in record:
                pdl = []
                for profile_desc in \
                        record[BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRID]:
                    uuidpair, versionpair = profile_desc[1]
                    pdl.append ((uuidpair[1], versionpair[1]))
                dict["profiles"] = pdl
            else:
                dict["profiles"] = []

            dict["provider"] = record.get (PROVIDER_NAME_ATTRID, None)

            dict["service-id"] = record.get (SERVICE_ID_ATTRID, None)

            # XXX the C version is buggy (retrieves an extra byte or two),
            # so get the service name here even though it may have already
            # been set
            dict["name"] = record.get (SERVICE_NAME_ATTRID, None)

            dict["handle"] = record.get (SERVICE_RECORD_HANDLE_ATTRID, None)
        
#        if LANGUAGE_BASE_ATTRID_LIST_ATTRID in record:
#            for triple in record[LANGUAGE_BASE_ATTRID_LIST_ATTRID]:
#                code_ISO639, encoding, base_offset = triple
#
#        if SERVICE_DESCRIPTION_ATTRID in record:
#            service_description = record[SERVICE_DESCRIPTION_ATTRID]

        if name is None:
            results.extend (dresults)
        else:
            results.extend ([ d for d in dresults if d["name"] == name ])
    return results
