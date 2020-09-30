import pytest
from scapy.all import *


# DUID_LLT basic instantiation
def test_DUIDLLTbasicinstantiation():
    a = DUID_LLT()
    assert a is not None

    # DUID_LLT basic build


def test_DUIDLLTbasicbuild():
    assert raw(
        DUID_LLT()) == b'\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DUID_LLT build with specific values 
def test_DUIDLLTbuildwithspecificvalues():
    assert raw(DUID_LLT(lladdr="ff:ff:ff:ff:ff:ff", timeval=0x11111111,
                        hwtype=0x2222)) == b'\x00\x01""\x11\x11\x11\x11\xff\xff\xff\xff\xff\xff'


# DUID_LLT basic dissection 
def test_DUIDLLTbasicdissection():
    a = DUID_LLT(raw(DUID_LLT()))
    assert a.type == 1 and a.hwtype == 1 and a.timeval == 0 and a.lladdr == "00:00:00:00:00:00"


# DUID_LLT dissection with specific values 
def test_DUIDLLTdissectionwithspecificvalues():
    a = DUID_LLT(b'\x00\x01""\x11\x11\x11\x11\xff\xff\xff\xff\xff\xff')
    assert a.type == 1 and a.hwtype == 0x2222 and a.timeval == 0x11111111 and a.lladdr == "ff:ff:ff:ff:ff:ff"


# DUID_EN basic instantiation
def test_DUIDENbasicinstantiation():
    a = DUID_EN()
    assert a is not None

    # DUID_EN basic build


def test_DUIDENbasicbuild():
    assert raw(DUID_EN()) == b'\x00\x02\x00\x00\x017'


# DUID_EN build with specific values 
def test_DUIDENbuildwithspecificvalues():
    assert raw(DUID_EN(enterprisenum=0x11111111,
                       id="iamastring")) == b'\x00\x02\x11\x11\x11\x11iamastring'


# DUID_EN basic dissection 
def test_DUIDENbasicdissection():
    a = DUID_EN(b'\x00\x02\x00\x00\x017')
    assert a.type == 2 and a.enterprisenum == 311


# DUID_EN dissection with specific values 
def test_DUIDENdissectionwithspecificvalues():
    a = DUID_EN(b'\x00\x02\x11\x11\x11\x11iamarawing')
    assert a.type == 2 and a.enterprisenum == 0x11111111 and a.id == b"iamarawing"


# DUID_LL basic instantiation
def test_DUIDLLbasicinstantiation():
    a = DUID_LL()
    assert a is not None

    # DUID_LL basic build


def test_DUIDLLbasicbuild():
    assert raw(DUID_LL()) == b'\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00'


# DUID_LL build with specific values 
def test_DUIDLLbuildwithspecificvalues():
    assert raw(DUID_LL(hwtype=1,
                       lladdr="ff:ff:ff:ff:ff:ff")) == b'\x00\x03\x00\x01\xff\xff\xff\xff\xff\xff'


# DUID_LL basic dissection 
def test_DUIDLLbasicdissection():
    a = DUID_LL(raw(DUID_LL()))
    assert a.type == 3 and a.hwtype == 1 and a.lladdr == "00:00:00:00:00:00"


# DUID_LL with specific values 
def test_DUIDLLwithspecificvalues():
    a = DUID_LL(b'\x00\x03\x00\x01\xff\xff\xff\xff\xff\xff')
    assert a.hwtype == 1 and a.lladdr == "ff:ff:ff:ff:ff:ff"


# DUID_UUID basic instantiation
def test_DUIDUUIDbasicinstantiation():
    a = DUID_UUID()
    assert a is not None


# DUID_UUID basic build
def test_DUIDUUIDbasicbuild():
    assert raw(DUID_UUID()) == b"\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"


# DUID_UUID build with specific values 
def test_DUIDUUIDbuildwithspecificvalues():
    assert raw(DUID_UUID(uuid="272adcca-138c-4e8d-b3f4-634e953128cf")) == \
           b"\x00\x04'*\xdc\xca\x13\x8cN\x8d\xb3\xf4cN\x951(\xcf"


# DUID_UUID basic dissection 
def test_DUIDUUIDbasicdissection():
    a = DUID_UUID(raw(DUID_UUID()))
    assert a.type == 4 and str(a.uuid) == "00000000-0000-0000-0000-000000000000"


# DUID_UUID with specific values 
def test_DUIDUUIDwithspecificvalues():
    a = DUID_UUID(b"\x00\x04'*\xdc\xca\x13\x8cN\x8d\xb3\xf4cN\x951(\xcf")
    assert a.type == 4 and str(a.uuid) == "272adcca-138c-4e8d-b3f4-634e953128cf"


# DHCP6 Opt Unknown basic instantiation
def test_DHCP6OptUnknownbasicinstantiation():
    a = DHCP6OptUnknown()
    assert a is not None

    # DHCP6 Opt Unknown basic build (default values)


def test_DHCP6OptUnknownbasicbuilddefaultvalues():
    assert raw(DHCP6OptUnknown()) == b'\x00\x00\x00\x00'


# DHCP6 Opt Unknown - len computation test 
def test_DHCP6OptUnknownlencomputationtest():
    assert raw(DHCP6OptUnknown(data="shouldbe9")) == b'\x00\x00\x00\tshouldbe9'


# DHCP6OptClientId basic instantiation
def test_DHCP6OptClientIdbasicinstantiation():
    a = DHCP6OptClientId()
    assert a is not None


# DHCP6OptClientId basic build 
def test_DHCP6OptClientIdbasicbuild():
    assert raw(DHCP6OptClientId()) == b'\x00\x01\x00\x00'


# DHCP6OptClientId instantiation with specific values 
def test_DHCP6OptClientIdinstantiationwithspecificvalues():
    assert raw(DHCP6OptClientId(duid="toto")) == b'\x00\x01\x00\x04toto'


# DHCP6OptClientId instantiation with DUID_LL 
def test_DHCP6OptClientIdinstantiationwithDUIDLL():
    assert raw(DHCP6OptClientId(
        duid=DUID_LL())) == b'\x00\x01\x00\n\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00'


# DHCP6OptClientId instantiation with DUID_LLT 
def test_DHCP6OptClientIdinstantiationwithDUIDLLT():
    assert raw(DHCP6OptClientId(
        duid=DUID_LLT())) == b'\x00\x01\x00\x0e\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DHCP6OptClientId instantiation with DUID_EN 
def test_DHCP6OptClientIdinstantiationwithDUIDEN():
    assert raw(DHCP6OptClientId(
        duid=DUID_EN())) == b'\x00\x01\x00\x06\x00\x02\x00\x00\x017'


# DHCP6OptClientId instantiation with specified length 
def test_DHCP6OptClientIdinstantiationwithspecifiedlength():
    assert raw(DHCP6OptClientId(optlen=80,
                                duid="somestring")) == b'\x00\x01\x00Psomestring'


# DHCP6OptClientId basic dissection 
def test_DHCP6OptClientIdbasicdissection():
    a = DHCP6OptClientId(b'\x00\x01\x00\x00')
    assert a.optcode == 1 and a.optlen == 0


# DHCP6OptClientId instantiation with specified length 
def test_DHCP6OptClientIdinstantiationwithspecifiedlength1():
    assert raw(DHCP6OptClientId(optlen=80,
                                duid="somestring")) == b'\x00\x01\x00Psomestring'


# DHCP6OptClientId basic dissection 
def test_DHCP6OptClientIdbasicdissection1():
    a = DHCP6OptClientId(b'\x00\x01\x00\x00')
    assert a.optcode == 1 and a.optlen == 0


# DHCP6OptClientId dissection with specific duid value 
def test_DHCP6OptClientIddissectionwithspecificduidvalue():
    a = DHCP6OptClientId(b'\x00\x01\x00\x04somerawing')
    assert a.optcode == 1 and a.optlen == 4 and isinstance(a.duid,
                                                           Raw) and a.duid.load == b'some' and isinstance(
        a.payload, DHCP6OptUnknown)


# DHCP6OptClientId dissection with specific DUID_LL as duid value 
def test_DHCP6OptClientIddissectionwithspecificDUIDLLasduidvalue():
    a = DHCP6OptClientId(
        b'\x00\x01\x00\n\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 1 and a.optlen == 10 and isinstance(a.duid,
                                                            DUID_LL) and a.duid.type == 3 and a.duid.hwtype == 1 and a.duid.lladdr == "00:00:00:00:00:00"


# DHCP6OptClientId dissection with specific DUID_LLT as duid value 
def test_DHCP6OptClientIddissectionwithspecificDUIDLLTasduidvalue():
    a = DHCP6OptClientId(
        b'\x00\x01\x00\x0e\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 1 and a.optlen == 14 and isinstance(a.duid,
                                                            DUID_LLT) and a.duid.type == 1 and a.duid.hwtype == 1 and a.duid.timeval == 0 and a.duid.lladdr == "00:00:00:00:00:00"


# DHCP6OptClientId dissection with specific DUID_EN as duid value 
def test_DHCP6OptClientIddissectionwithspecificDUIDENasduidvalue():
    a = DHCP6OptClientId(b'\x00\x01\x00\x06\x00\x02\x00\x00\x017')
    assert a.optcode == 1 and a.optlen == 6 and isinstance(a.duid,
                                                           DUID_EN) and a.duid.type == 2 and a.duid.enterprisenum == 311 and a.duid.id == b""


# DHCP6OptServerId basic instantiation
def test_DHCP6OptServerIdbasicinstantiation():
    a = DHCP6OptServerId()
    assert a is not None


# DHCP6OptServerId basic build
def test_DHCP6OptServerIdbasicbuild():
    assert raw(DHCP6OptServerId()) == b'\x00\x02\x00\x00'


# DHCP6OptServerId basic build with specific values 
def test_DHCP6OptServerIdbasicbuildwithspecificvalues():
    assert raw(DHCP6OptServerId(duid="toto")) == b'\x00\x02\x00\x04toto'


# DHCP6OptServerId instantiation with DUID_LL 
def test_DHCP6OptServerIdinstantiationwithDUIDLL():
    assert raw(DHCP6OptServerId(
        duid=DUID_LL())) == b'\x00\x02\x00\n\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00'


# DHCP6OptServerId instantiation with DUID_LLT 
def test_DHCP6OptServerIdinstantiationwithDUIDLLT():
    assert raw(DHCP6OptServerId(
        duid=DUID_LLT())) == b'\x00\x02\x00\x0e\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DHCP6OptServerId instantiation with DUID_EN 
def test_DHCP6OptServerIdinstantiationwithDUIDEN():
    assert raw(DHCP6OptServerId(
        duid=DUID_EN())) == b'\x00\x02\x00\x06\x00\x02\x00\x00\x017'


# DHCP6OptServerId instantiation with specified length 
def test_DHCP6OptServerIdinstantiationwithspecifiedlength():
    assert raw(DHCP6OptServerId(optlen=80,
                                duid="somestring")) == b'\x00\x02\x00Psomestring'


# DHCP6OptServerId basic dissection 
def test_DHCP6OptServerIdbasicdissection():
    a = DHCP6OptServerId(b'\x00\x02\x00\x00')
    assert a.optcode == 2 and a.optlen == 0


# DHCP6OptServerId dissection with specific duid value 
def test_DHCP6OptServerIddissectionwithspecificduidvalue():
    a = DHCP6OptServerId(b'\x00\x02\x00\x04somerawing')
    assert a.optcode == 2 and a.optlen == 4 and isinstance(a.duid,
                                                           Raw) and a.duid.load == b'some' and isinstance(
        a.payload, DHCP6OptUnknown)


# DHCP6OptServerId dissection with specific DUID_LL as duid value 
def test_DHCP6OptServerIddissectionwithspecificDUIDLLasduidvalue():
    a = DHCP6OptServerId(
        b'\x00\x02\x00\n\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 2 and a.optlen == 10 and isinstance(a.duid,
                                                            DUID_LL) and a.duid.type == 3 and a.duid.hwtype == 1 and a.duid.lladdr == "00:00:00:00:00:00"


# DHCP6OptServerId dissection with specific DUID_LLT as duid value 
def test_DHCP6OptServerIddissectionwithspecificDUIDLLTasduidvalue():
    a = DHCP6OptServerId(
        b'\x00\x02\x00\x0e\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 2 and a.optlen == 14 and isinstance(a.duid,
                                                            DUID_LLT) and a.duid.type == 1 and a.duid.hwtype == 1 and a.duid.timeval == 0 and a.duid.lladdr == "00:00:00:00:00:00"


# DHCP6OptServerId dissection with specific DUID_EN as duid value 
def test_DHCP6OptServerIddissectionwithspecificDUIDENasduidvalue():
    a = DHCP6OptServerId(b'\x00\x02\x00\x06\x00\x02\x00\x00\x017')
    assert a.optcode == 2 and a.optlen == 6 and isinstance(a.duid,
                                                           DUID_EN) and a.duid.type == 2 and a.duid.enterprisenum == 311 and a.duid.id == b""


# DHCP6OptIAAddress - Basic Instantiation
def test_DHCP6OptIAAddressBasicInstantiation():
    assert raw(
        DHCP6OptIAAddress()) == b'\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DHCP6OptIAAddress - Basic Dissection 
def test_DHCP6OptIAAddressBasicDissection():
    a = DHCP6OptIAAddress(
        b'\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 5 and a.optlen == 24 and a.addr == "::" and a.preflft == 0 and a.validlft == 0 and a.iaaddropts == []


# DHCP6OptIAAddress - Instantiation with specific values 
def test_DHCP6OptIAAddressInstantiationwithspecificvalues():
    assert raw(DHCP6OptIAAddress(optlen=0x1111, addr="2222:3333::5555",
                                 preflft=0x66666666, validlft=0x77777777,
                                 iaaddropts="somestring")) == b'\x00\x05\x11\x11""33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00UUffffwwwwsomestring'


# DHCP6OptIAAddress - Instantiation with specific values (default optlen computation) 
def test_DHCP6OptIAAddressInstantiationwithspecificvaluesdefaultoptlencomputation():
    assert raw(DHCP6OptIAAddress(addr="2222:3333::5555", preflft=0x66666666,
                                 validlft=0x77777777,
                                 iaaddropts="somestring")) == b'\x00\x05\x00"""33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00UUffffwwwwsomestring'


# DHCP6OptIAAddress - Dissection with specific values 
def test_DHCP6OptIAAddressDissectionwithspecificvalues():
    a = DHCP6OptIAAddress(
        b'\x00\x05\x00"""33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00UUffffwwwwsomerawing')
    assert a.optcode == 5 and a.optlen == 34 and a.addr == "2222:3333::5555" and a.preflft == 0x66666666 and a.validlft == 0x77777777 and \
           a.iaaddropts[0].load == b"somerawing"


# DHCP6OptIA_NA - Basic Instantiation
def test_DHCP6OptIANABasicInstantiation():
    assert raw(
        DHCP6OptIA_NA()) == b'\x00\x03\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DHCP6OptIA_NA - Basic Dissection 
def test_DHCP6OptIANABasicDissection():
    a = DHCP6OptIA_NA(
        b'\x00\x03\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 3 and a.optlen == 12 and a.iaid == 0 and a.T1 == 0 and a.T2 == 0 and a.ianaopts == []


# DHCP6OptIA_NA - Instantiation with specific values (keep automatic length computation) 
def test_DHCP6OptIANAInstantiationwithspecificvalueskeepautomaticlengthcomputation():
    assert raw(DHCP6OptIA_NA(iaid=0x22222222, T1=0x33333333,
                             T2=0x44444444)) == b'\x00\x03\x00\x0c""""3333DDDD'


# DHCP6OptIA_NA - Instantiation with specific values (forced optlen) 
def test_DHCP6OptIANAInstantiationwithspecificvaluesforcedoptlen():
    assert raw(DHCP6OptIA_NA(optlen=0x1111, iaid=0x22222222, T1=0x33333333,
                             T2=0x44444444)) == b'\x00\x03\x11\x11""""3333DDDD'


# DHCP6OptIA_NA - Instantiation with a list of IA Addresses (optlen automatic computation) 
def test_DHCP6OptIANAInstantiationwithalistofIAAddressesoptlenautomaticcomputation():
    assert raw(DHCP6OptIA_NA(iaid=0x22222222, T1=0x33333333, T2=0x44444444,
                             ianaopts=[DHCP6OptIAAddress(),
                                       DHCP6OptIAAddress()])) == b'\x00\x03\x00D""""3333DDDD\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DHCP6OptIA_NA - Dissection with specific values 
def test_DHCP6OptIANADissectionwithspecificvalues():
    a = DHCP6OptIA_NA(
        b'\x00\x03\x00L""""3333DDDD\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 3 and a.optlen == 76 and a.iaid == 0x22222222 and a.T1 == 0x33333333 and a.T2 == 0x44444444 and len(
        a.ianaopts) == 2 and isinstance(a.ianaopts[0],
                                        DHCP6OptIAAddress) and isinstance(
        a.ianaopts[1], DHCP6OptIAAddress)


# DHCP6OptIA_NA - Instantiation with a list of different opts: IA Address and Status Code (optlen automatic computation) 
def test_DHCP6OptIANAInstantiationwithalistofdifferentoptsIAAddressandStatusCodeoptlenautomaticcomputation():
    assert raw(DHCP6OptIA_NA(iaid=0x22222222, T1=0x33333333, T2=0x44444444,
                             ianaopts=[DHCP6OptIAAddress(),
                                       DHCP6OptStatusCode(statuscode=0xff,
                                                          statusmsg="Hello")])) == b'\x00\x03\x003""""3333DDDD\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\x00\x07\x00\xffHello'


# DHCP6OptIA_TA - Basic Instantiation
def test_DHCP6OptIATABasicInstantiation():
    assert raw(DHCP6OptIA_TA()) == b'\x00\x04\x00\x04\x00\x00\x00\x00'


# DHCP6OptIA_TA - Basic Dissection 
def test_DHCP6OptIATABasicDissection():
    a = DHCP6OptIA_TA(b'\x00\x04\x00\x04\x00\x00\x00\x00')
    assert a.optcode == 4 and a.optlen == 4 and a.iaid == 0 and a.iataopts == []


# DHCP6OptIA_TA - Instantiation with specific values 
def test_DHCP6OptIATAInstantiationwithspecificvalues():
    assert raw(DHCP6OptIA_TA(optlen=0x1111, iaid=0x22222222,
                             iataopts=[DHCP6OptIAAddress(),
                                       DHCP6OptIAAddress()])) == b'\x00\x04\x11\x11""""\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DHCP6OptIA_TA - Dissection with specific values 
def test_DHCP6OptIATADissectionwithspecificvalues():
    a = DHCP6OptIA_TA(
        b'\x00\x04\x11\x11""""\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    a.optcode == 4 and a.optlen == 0x1111 and a.iaid == 0x22222222 and len(
        a.iataopts) == 2 and isinstance(a.iataopts[0],
                                        DHCP6OptIAAddress) and isinstance(
        a.iataopts[1], DHCP6OptIAAddress)


# DHCP6OptIA_TA - Instantiation with a list of different opts: IA Address and Status Code (optlen automatic computation) 
def test_DHCP6OptIATAInstantiationwithalistofdifferentoptsIAAddressandStatusCodeoptlenautomaticcomputation():
    assert raw(DHCP6OptIA_TA(iaid=0x22222222, iataopts=[DHCP6OptIAAddress(),
                                                        DHCP6OptStatusCode(
                                                            statuscode=0xff,
                                                            statusmsg="Hello")])) == b'\x00\x04\x00+""""\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\x00\x07\x00\xffHello'


# DHCP6OptOptReq - Basic Instantiation
def test_DHCP6OptOptReqBasicInstantiation():
    assert raw(DHCP6OptOptReq()) == b'\x00\x06\x00\x04\x00\x17\x00\x18'


# DHCP6OptOptReq - optlen field computation 
def test_DHCP6OptOptReqoptlenfieldcomputation():
    assert raw(DHCP6OptOptReq(reqopts=[1, 2, 3,
                                       4])) == b'\x00\x06\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04'


# DHCP6OptOptReq - instantiation with empty list 
def test_DHCP6OptOptReqinstantiationwithemptylist():
    assert raw(DHCP6OptOptReq(reqopts=[])) == b'\x00\x06\x00\x00'


# DHCP6OptOptReq - Basic dissection 
def test_DHCP6OptOptReqBasicdissection():
    a = DHCP6OptOptReq(b'\x00\x06\x00\x00')
    assert a.optcode == 6 and a.optlen == 0 and a.reqopts == [23, 24]


# DHCP6OptOptReq - Dissection with specific value 
def test_DHCP6OptOptReqDissectionwithspecificvalue():
    a = DHCP6OptOptReq(b'\x00\x06\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04')
    assert a.optcode == 6 and a.optlen == 8 and a.reqopts == [1, 2, 3, 4]


# DHCP6OptOptReq - repr 
def test_DHCP6OptOptReqrepr():
    a = DHCP6OptOptReq(b'\x00\x06\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04')
    a.show()
    assert a is not None


# DHCP6OptPref - Basic instantiation
def test_DHCP6OptPrefBasicinstantiation():
    assert raw(DHCP6OptPref()) == b'\x00\x07\x00\x01\xff'


# DHCP6OptPref - Instantiation with specific values 
def test_DHCP6OptPrefInstantiationwithspecificvalues():
    assert raw(
        DHCP6OptPref(optlen=0xffff, prefval=0x11)) == b'\x00\x07\xff\xff\x11'


# DHCP6OptPref - Basic Dissection 
def test_DHCP6OptPrefBasicDissection():
    a = DHCP6OptPref(b'\x00\x07\x00\x01\xff')
    assert a.optcode == 7 and a.optlen == 1 and a.prefval == 255


# DHCP6OptPref - Dissection with specific values 
def test_DHCP6OptPrefDissectionwithspecificvalues():
    a = DHCP6OptPref(b'\x00\x07\xff\xff\x11')
    assert a.optcode == 7 and a.optlen == 0xffff and a.prefval == 0x11


# DHCP6OptElapsedTime - Basic Instantiation
def test_DHCP6OptElapsedTimeBasicInstantiation():
    assert raw(DHCP6OptElapsedTime()) == b'\x00\x08\x00\x02\x00\x00'


# DHCP6OptElapsedTime - Instantiation with specific elapsedtime value 
def test_DHCP6OptElapsedTimeInstantiationwithspecificelapsedtimevalue():
    assert raw(
        DHCP6OptElapsedTime(elapsedtime=421)) == b'\x00\x08\x00\x02\x01\xa5'


# DHCP6OptElapsedTime - Basic Dissection 
def test_DHCP6OptElapsedTimeBasicDissection():
    a = DHCP6OptElapsedTime(b'\x00\x08\x00\x02\x00\x00')
    assert a.optcode == 8 and a.optlen == 2 and a.elapsedtime == 0


# DHCP6OptElapsedTime - Dissection with specific values 
def test_DHCP6OptElapsedTimeDissectionwithspecificvalues():
    a = DHCP6OptElapsedTime(b'\x00\x08\x00\x02\x01\xa5')
    assert a.optcode == 8 and a.optlen == 2 and a.elapsedtime == 421


# DHCP6OptElapsedTime - Repr 
def test_DHCP6OptElapsedTimeRepr():
    a = DHCP6OptElapsedTime(b'\x00\x08\x00\x02\x01\xa5')
    a.show()
    assert a is not None

    # DHCP6OptServerUnicast - Basic Instantiation


def test_DHCP6OptServerUnicastBasicInstantiation():
    assert raw(
        DHCP6OptServerUnicast()) == b'\x00\x0c\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DHCP6OptServerUnicast - Instantiation with specific values (test 1) 
def test_DHCP6OptServerUnicastInstantiationwithspecificvaluestest1():
    assert raw(DHCP6OptServerUnicast(
        srvaddr="2001::1")) == b'\x00\x0c\x00\x10 \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


# DHCP6OptServerUnicast - Instantiation with specific values (test 2) 
def test_DHCP6OptServerUnicastInstantiationwithspecificvaluestest2():
    assert raw(DHCP6OptServerUnicast(srvaddr="2001::1",
                                     optlen=42)) == b'\x00\x0c\x00* \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


# DHCP6OptServerUnicast - Dissection with default values 
def test_DHCP6OptServerUnicastDissectionwithdefaultvalues():
    a = DHCP6OptServerUnicast(
        b'\x00\x0c\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    a.optcode == 12 and a.optlen == 16 and a.srvaddr == "::"


# DHCP6OptServerUnicast - Dissection with specific values (test 1) 
def test_DHCP6OptServerUnicastDissectionwithspecificvaluestest1():
    a = DHCP6OptServerUnicast(
        b'\x00\x0c\x00\x10 \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 12 and a.optlen == 16 and a.srvaddr == "2001::1"


# DHCP6OptServerUnicast - Dissection with specific values (test 2) 
def test_DHCP6OptServerUnicastDissectionwithspecificvaluestest2():
    a = DHCP6OptServerUnicast(
        b'\x00\x0c\x00* \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 12 and a.optlen == 42 and a.srvaddr == "2001::1"


# DHCP6OptStatusCode - Basic Instantiation
def test_DHCP6OptStatusCodeBasicInstantiation():
    assert raw(DHCP6OptStatusCode()) == b'\x00\r\x00\x02\x00\x00'


# DHCP6OptStatusCode - Instantiation with specific values 
def test_DHCP6OptStatusCodeInstantiationwithspecificvalues():
    assert raw(DHCP6OptStatusCode(optlen=42, statuscode=0xff,
                                  statusmsg="Hello")) == b'\x00\r\x00*\x00\xffHello'


# DHCP6OptStatusCode - Automatic Length computation 
def test_DHCP6OptStatusCodeAutomaticLengthcomputation():
    assert raw(DHCP6OptStatusCode(statuscode=0xff,
                                  statusmsg="Hello")) == b'\x00\r\x00\x07\x00\xffHello'


# DHCP6OptRapidCommit - Basic Instantiation
def test_DHCP6OptRapidCommitBasicInstantiation():
    assert raw(DHCP6OptRapidCommit()) == b'\x00\x0e\x00\x00'


# DHCP6OptRapidCommit - Basic Dissection 
def test_DHCP6OptRapidCommitBasicDissection():
    a = DHCP6OptRapidCommit(b'\x00\x0e\x00\x00')
    assert a.optcode == 14 and a.optlen == 0


# DHCP6OptUserClass - Basic Instantiation
def test_DHCP6OptUserClassBasicInstantiation():
    assert raw(DHCP6OptUserClass()) == b'\x00\x0f\x00\x00'


# DHCP6OptUserClass - Basic Dissection 
def test_DHCP6OptUserClassBasicDissection():
    a = DHCP6OptUserClass(b'\x00\x0f\x00\x00')
    assert a.optcode == 15 and a.optlen == 0 and a.userclassdata == []


# DHCP6OptUserClass - Instantiation with one user class data rawucture 
def test_DHCP6OptUserClassInstantiationwithoneuserclassdatarawucture():
    assert raw(DHCP6OptUserClass(userclassdata=[USER_CLASS_DATA(
        data="something")])) == b'\x00\x0f\x00\x0b\x00\tsomething'


# DHCP6OptUserClass - Dissection with one user class data rawucture 
def test_DHCP6OptUserClassDissectionwithoneuserclassdatarawucture():
    a = DHCP6OptUserClass(b'\x00\x0f\x00\x0b\x00\tsomething')
    assert a.optcode == 15 and a.optlen == 11 and len(
        a.userclassdata) == 1 and isinstance(a.userclassdata[0],
                                             USER_CLASS_DATA) and \
           a.userclassdata[0].len == 9 and a.userclassdata[
               0].data == b'something'


# DHCP6OptUserClass - Instantiation with two user class data rawuctures 
def test_DHCP6OptUserClassInstantiationwithtwouserclassdatarawuctures():
    assert raw(DHCP6OptUserClass(
        userclassdata=[USER_CLASS_DATA(data="something"), USER_CLASS_DATA(
            data="somethingelse")])) == b'\x00\x0f\x00\x1a\x00\tsomething\x00\rsomethingelse'


# DHCP6OptUserClass - Dissection with two user class data rawuctures 
def test_DHCP6OptUserClassDissectionwithtwouserclassdatarawuctures():
    a = DHCP6OptUserClass(b'\x00\x0f\x00\x1a\x00\tsomething\x00\rsomethingelse')
    assert a.optcode == 15 and a.optlen == 26 and len(
        a.userclassdata) == 2 and isinstance(a.userclassdata[0],
                                             USER_CLASS_DATA) and isinstance(
        a.userclassdata[1], USER_CLASS_DATA) and a.userclassdata[0].len == 9 and \
           a.userclassdata[0].data == b'something' and a.userclassdata[
               1].len == 13 and a.userclassdata[1].data == b'somethingelse'


# DHCP6OptVendorClass - Basic Instantiation
def test_DHCP6OptVendorClassBasicInstantiation():
    assert raw(DHCP6OptVendorClass()) == b'\x00\x10\x00\x04\x00\x00\x00\x00'


# DHCP6OptVendorClass - Basic Dissection 
def test_DHCP6OptVendorClassBasicDissection():
    a = DHCP6OptVendorClass(b'\x00\x10\x00\x04\x00\x00\x00\x00')
    assert a.optcode == 16 and a.optlen == 4 and a.enterprisenum == 0 and a.vcdata == []


# DHCP6OptVendorClass - Instantiation with one vendor class data rawucture 
def test_DHCP6OptVendorClassInstantiationwithonevendorclassdatarawucture():
    assert raw(DHCP6OptVendorClass(vcdata=[VENDOR_CLASS_DATA(
        data="something")])) == b'\x00\x10\x00\x0f\x00\x00\x00\x00\x00\tsomething'


# DHCP6OptVendorClass - Dissection with one vendor class data rawucture 
def test_DHCP6OptVendorClassDissectionwithonevendorclassdatarawucture():
    a = DHCP6OptVendorClass(b'\x00\x10\x00\x0f\x00\x00\x00\x00\x00\tsomething')
    assert a.optcode == 16 and a.optlen == 15 and a.enterprisenum == 0 and len(
        a.vcdata) == 1 and isinstance(a.vcdata[0], VENDOR_CLASS_DATA) and \
           a.vcdata[0].len == 9 and a.vcdata[0].data == b'something'


# DHCP6OptVendorClass - Instantiation with two vendor class data rawuctures 
def test_DHCP6OptVendorClassInstantiationwithtwovendorclassdatarawuctures():
    assert raw(DHCP6OptVendorClass(vcdata=[VENDOR_CLASS_DATA(data="something"),
                                           VENDOR_CLASS_DATA(
                                               data="somethingelse")])) == b'\x00\x10\x00\x1e\x00\x00\x00\x00\x00\tsomething\x00\rsomethingelse'


# DHCP6OptVendorClass - Dissection with two vendor class data rawuctures 
def test_DHCP6OptVendorClassDissectionwithtwovendorclassdatarawuctures():
    a = DHCP6OptVendorClass(
        b'\x00\x10\x00\x1e\x00\x00\x00\x00\x00\tsomething\x00\rsomethingelse')
    assert a.optcode == 16 and a.optlen == 30 and a.enterprisenum == 0 and len(
        a.vcdata) == 2 and isinstance(a.vcdata[0],
                                      VENDOR_CLASS_DATA) and isinstance(
        a.vcdata[1], VENDOR_CLASS_DATA) and a.vcdata[0].len == 9 and a.vcdata[
               0].data == b'something' and a.vcdata[1].len == 13 and a.vcdata[
               1].data == b'somethingelse'


# DHCP6OptVendorSpecificInfo - Basic Instantiation
def test_DHCP6OptVendorSpecificInfoBasicInstantiation():
    assert raw(
        DHCP6OptVendorSpecificInfo()) == b'\x00\x11\x00\x04\x00\x00\x00\x00'


# DHCP6OptVendorSpecificInfo - Basic Dissection 
def test_DHCP6OptVendorSpecificInfoBasicDissection():
    a = DHCP6OptVendorSpecificInfo(b'\x00\x11\x00\x04\x00\x00\x00\x00')
    assert a.optcode == 17 and a.optlen == 4 and a.enterprisenum == 0


# DHCP6OptVendorSpecificInfo - Instantiation with specific values (one option) 
def test_DHCP6OptVendorSpecificInfoInstantiationwithspecificvaluesoneoption():
    assert raw(DHCP6OptVendorSpecificInfo(enterprisenum=0xeeeeeeee, vso=[
        VENDOR_SPECIFIC_OPTION(optcode=43,
                               optdata="something")])) == b'\x00\x11\x00\x11\xee\xee\xee\xee\x00+\x00\tsomething'


# DHCP6OptVendorSpecificInfo - Dissection with with specific values (one option) 
def test_DHCP6OptVendorSpecificInfoDissectionwithwithspecificvaluesoneoption():
    a = DHCP6OptVendorSpecificInfo(
        b'\x00\x11\x00\x11\xee\xee\xee\xee\x00+\x00\tsomething')
    assert a.optcode == 17 and a.optlen == 17 and a.enterprisenum == 0xeeeeeeee and len(
        a.vso) == 1 and isinstance(a.vso[0], VENDOR_SPECIFIC_OPTION) and a.vso[
               0].optlen == 9 and a.vso[0].optdata == b'something'


# DHCP6OptVendorSpecificInfo - Instantiation with specific values (two options) 
def test_DHCP6OptVendorSpecificInfoInstantiationwithspecificvaluestwooptions():
    assert raw(DHCP6OptVendorSpecificInfo(enterprisenum=0xeeeeeeee, vso=[
        VENDOR_SPECIFIC_OPTION(optcode=43, optdata="something"),
        VENDOR_SPECIFIC_OPTION(optcode=42,
                               optdata="somethingelse")])) == b'\x00\x11\x00"\xee\xee\xee\xee\x00+\x00\tsomething\x00*\x00\rsomethingelse'


# DHCP6OptVendorSpecificInfo - Dissection with with specific values (two options) 
def test_DHCP6OptVendorSpecificInfoDissectionwithwithspecificvaluestwooptions():
    a = DHCP6OptVendorSpecificInfo(
        b'\x00\x11\x00"\xee\xee\xee\xee\x00+\x00\tsomething\x00*\x00\rsomethingelse')
    assert a.optcode == 17 and a.optlen == 34 and a.enterprisenum == 0xeeeeeeee and len(
        a.vso) == 2 and isinstance(a.vso[0],
                                   VENDOR_SPECIFIC_OPTION) and isinstance(
        a.vso[1], VENDOR_SPECIFIC_OPTION) and a.vso[0].optlen == 9 and a.vso[
               0].optdata == b'something' and a.vso[1].optlen == 13 and a.vso[
               1].optdata == b'somethingelse'


# DHCP6OptIfaceId - Basic Instantiation
def test_DHCP6OptIfaceIdBasicInstantiation():
    assert raw(DHCP6OptIfaceId()) == b'\x00\x12\x00\x00'


# DHCP6OptIfaceId - Basic Dissection 
def test_DHCP6OptIfaceIdBasicDissection():
    a = DHCP6OptIfaceId(b'\x00\x12\x00\x00')
    assert a.optcode == 18 and a.optlen == 0


# DHCP6OptIfaceId - Instantiation with specific value 
def test_DHCP6OptIfaceIdInstantiationwithspecificvalue():
    assert raw(
        DHCP6OptIfaceId(ifaceid="something")) == b'\x00\x12\x00\x09something'


# DHCP6OptIfaceId - Dissection with specific value 
def test_DHCP6OptIfaceIdDissectionwithspecificvalue():
    a = DHCP6OptIfaceId(b'\x00\x12\x00\x09something')
    assert a.optcode == 18 and a.optlen == 9 and a.ifaceid == b"something"


# DHCP6OptReconfMsg - Basic Instantiation
def test_DHCP6OptReconfMsgBasicInstantiation():
    assert raw(DHCP6OptReconfMsg()) == b'\x00\x13\x00\x01\x0b'


# DHCP6OptReconfMsg - Basic Dissection 
def test_DHCP6OptReconfMsgBasicDissection():
    a = DHCP6OptReconfMsg(b'\x00\x13\x00\x01\x0b')
    assert a.optcode == 19 and a.optlen == 1 and a.msgtype == 11


# DHCP6OptReconfMsg - Instantiation with specific values 
def test_DHCP6OptReconfMsgInstantiationwithspecificvalues():
    assert raw(
        DHCP6OptReconfMsg(optlen=4, msgtype=5)) == b'\x00\x13\x00\x04\x05'


# DHCP6OptReconfMsg - Dissection with specific values 
def test_DHCP6OptReconfMsgDissectionwithspecificvalues():
    a = DHCP6OptReconfMsg(b'\x00\x13\x00\x04\x05')
    assert a.optcode == 19 and a.optlen == 4 and a.msgtype == 5


# DHCP6OptReconfAccept - Basic Instantiation
def test_DHCP6OptReconfAcceptBasicInstantiation():
    assert raw(DHCP6OptReconfAccept()) == b'\x00\x14\x00\x00'


# DHCP6OptReconfAccept - Basic Dissection 
def test_DHCP6OptReconfAcceptBasicDissection():
    a = DHCP6OptReconfAccept(b'\x00\x14\x00\x00')
    assert a.optcode == 20 and a.optlen == 0


# DHCP6OptReconfAccept - Instantiation with specific values 
def test_DHCP6OptReconfAcceptInstantiationwithspecificvalues():
    assert raw(DHCP6OptReconfAccept(optlen=23)) == b'\x00\x14\x00\x17'


# DHCP6OptReconfAccept - Dssection with specific values 
def test_DHCP6OptReconfAcceptDssectionwithspecificvalues():
    a = DHCP6OptReconfAccept(b'\x00\x14\x00\x17')
    assert a.optcode == 20 and a.optlen == 23


# DHCP6OptSIPDomains - Basic Instantiation
def test_DHCP6OptSIPDomainsBasicInstantiation():
    assert raw(DHCP6OptSIPDomains()) == b'\x00\x15\x00\x00'


# DHCP6OptSIPDomains - Basic Dissection 
def test_DHCP6OptSIPDomainsBasicDissection():
    a = DHCP6OptSIPDomains(b'\x00\x15\x00\x00')
    assert a.optcode == 21 and a.optlen == 0 and a.sipdomains == []


# DHCP6OptSIPDomains - Instantiation with one domain 
def test_DHCP6OptSIPDomainsInstantiationwithonedomain():
    assert raw(DHCP6OptSIPDomains(sipdomains=[
        "toto.example.org"])) == b'\x00\x15\x00\x12\x04toto\x07example\x03org\x00'


# DHCP6OptSIPDomains - Dissection with one domain 
def test_DHCP6OptSIPDomainsDissectionwithonedomain():
    a = DHCP6OptSIPDomains(b'\x00\x15\x00\x12\x04toto\x07example\x03org\x00')
    assert a.optcode == 21 and a.optlen == 18 and len(a.sipdomains) == 1 and \
           a.sipdomains[0] == "toto.example.org."


# DHCP6OptSIPDomains - Instantiation with two domains 
def test_DHCP6OptSIPDomainsInstantiationwithtwodomains():
    assert raw(DHCP6OptSIPDomains(sipdomains=["toto.example.org",
                                              "titi.example.org"])) == b'\x00\x15\x00$\x04toto\x07example\x03org\x00\x04titi\x07example\x03org\x00'


# DHCP6OptSIPDomains - Dissection with two domains 
def test_DHCP6OptSIPDomainsDissectionwithtwodomains():
    a = DHCP6OptSIPDomains(
        b'\x00\x15\x00$\x04toto\x07example\x03org\x00\x04TITI\x07example\x03org\x00')
    assert a.optcode == 21 and a.optlen == 36 and len(a.sipdomains) == 2 and \
           a.sipdomains[0] == "toto.example.org." and a.sipdomains[
               1] == "TITI.example.org."


# DHCP6OptSIPDomains - Enforcing only one dot at end of domain 
def test_DHCP6OptSIPDomainsEnforcingonlyonedotatendofdomain():
    assert raw(DHCP6OptSIPDomains(sipdomains=[
        "toto.example.org."])) == b'\x00\x15\x00\x12\x04toto\x07example\x03org\x00'


# DHCP6OptSIPServers - Basic Instantiation
def test_DHCP6OptSIPServersBasicInstantiation():
    assert raw(DHCP6OptSIPServers()) == b'\x00\x16\x00\x00'


# DHCP6OptSIPServers - Basic Dissection 
def test_DHCP6OptSIPServersBasicDissection():
    a = DHCP6OptSIPServers(b'\x00\x16\x00\x00')
    assert a.optcode == 22 and a.optlen == 0 and a.sipservers == []


# DHCP6OptSIPServers - Instantiation with specific values (1 address) 
def test_DHCP6OptSIPServersInstantiationwithspecificvalues1address():
    assert raw(DHCP6OptSIPServers(sipservers=[
        "2001:db8::1"])) == b'\x00\x16\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


# DHCP6OptSIPServers - Dissection with specific values (1 address) 
def test_DHCP6OptSIPServersDissectionwithspecificvalues1address():
    a = DHCP6OptSIPServers(
        b'\x00\x16\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 22 and a.optlen == 16 and len(a.sipservers) == 1 and \
           a.sipservers[0] == "2001:db8::1"


# DHCP6OptSIPServers - Instantiation with specific values (2 addresses) 
def test_DHCP6OptSIPServersInstantiationwithspecificvalues2addresses():
    assert raw(DHCP6OptSIPServers(sipservers=["2001:db8::1",
                                              "2001:db8::2"])) == b'\x00\x16\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


# DHCP6OptSIPServers - Dissection with specific values (2 addresses) 
def test_DHCP6OptSIPServersDissectionwithspecificvalues2addresses():
    a = DHCP6OptSIPServers(
        b'\x00\x16\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 22 and a.optlen == 32 and len(a.sipservers) == 2 and \
           a.sipservers[0] == "2001:db8::1" and a.sipservers[1] == "2001:db8::2"


# DHCP6OptDNSServers - Basic Instantiation
def test_DHCP6OptDNSServersBasicInstantiation():
    assert raw(DHCP6OptDNSServers()) == b'\x00\x17\x00\x00'


# DHCP6OptDNSServers - Basic Dissection 
def test_DHCP6OptDNSServersBasicDissection():
    a = DHCP6OptDNSServers(b'\x00\x17\x00\x00')
    assert a.optcode == 23 and a.optlen == 0 and a.dnsservers == []


# DHCP6OptDNSServers - Instantiation with specific values (1 address) 
def test_DHCP6OptDNSServersInstantiationwithspecificvalues1address():
    assert raw(DHCP6OptDNSServers(dnsservers=[
        "2001:db8::1"])) == b'\x00\x17\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


# DHCP6OptDNSServers - Dissection with specific values (1 address) 
def test_DHCP6OptDNSServersDissectionwithspecificvalues1address():
    a = DHCP6OptDNSServers(
        b'\x00\x17\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 23 and a.optlen == 16 and len(a.dnsservers) == 1 and \
           a.dnsservers[0] == "2001:db8::1"


# DHCP6OptDNSServers - Instantiation with specific values (2 addresses) 
def test_DHCP6OptDNSServersInstantiationwithspecificvalues2addresses():
    assert raw(DHCP6OptDNSServers(dnsservers=["2001:db8::1",
                                              "2001:db8::2"])) == b'\x00\x17\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


# DHCP6OptDNSServers - Dissection with specific values (2 addresses) 
def test_DHCP6OptDNSServersDissectionwithspecificvalues2addresses():
    a = DHCP6OptDNSServers(
        b'\x00\x17\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 23 and a.optlen == 32 and len(a.dnsservers) == 2 and \
           a.dnsservers[0] == "2001:db8::1" and a.dnsservers[1] == "2001:db8::2"


# DHCP6OptDNSDomains - Basic Instantiation
def test_DHCP6OptDNSDomainsBasicInstantiation():
    assert raw(DHCP6OptDNSDomains()) == b'\x00\x18\x00\x00'


# DHCP6OptDNSDomains - Basic Dissection 
def test_DHCP6OptDNSDomainsBasicDissection():
    a = DHCP6OptDNSDomains(b'\x00\x18\x00\x00')
    assert a.optcode == 24 and a.optlen == 0 and a.dnsdomains == []


# DHCP6OptDNSDomains - Instantiation with specific values (1 domain) 
def test_DHCP6OptDNSDomainsInstantiationwithspecificvalues1domain():
    assert raw(DHCP6OptDNSDomains(dnsdomains=[
        "toto.example.com."])) == b'\x00\x18\x00\x12\x04toto\x07example\x03com\x00'


# DHCP6OptDNSDomains - Dissection with specific values (1 domain) 
def test_DHCP6OptDNSDomainsDissectionwithspecificvalues1domain():
    a = DHCP6OptDNSDomains(b'\x00\x18\x00\x12\x04toto\x07example\x03com\x00')
    assert a.optcode == 24 and a.optlen == 18 and len(a.dnsdomains) == 1 and \
           a.dnsdomains[0] == "toto.example.com."


# DHCP6OptDNSDomains - Instantiation with specific values (2 domains) 
def test_DHCP6OptDNSDomainsInstantiationwithspecificvalues2domains():
    assert raw(DHCP6OptDNSDomains(dnsdomains=["toto.example.com.",
                                              "titi.example.com."])) == b'\x00\x18\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00'


# DHCP6OptDNSDomains - Dissection with specific values (2 domains) 
def test_DHCP6OptDNSDomainsDissectionwithspecificvalues2domains():
    a = DHCP6OptDNSDomains(
        b'\x00\x18\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00')
    assert a.optcode == 24 and a.optlen == 36 and len(a.dnsdomains) == 2 and \
           a.dnsdomains[0] == "toto.example.com." and a.dnsdomains[
               1] == "titi.example.com."


# DHCP6OptIAPrefix - Basic Instantiation
def test_DHCP6OptIAPrefixBasicInstantiation():
    assert raw(
        DHCP6OptIAPrefix()) == b'\x00\x1a\x00\x19\x00\x00\x00\x00\x00\x00\x00\x000 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DHCP6OptIA_PD - Basic Instantiation
def test_DHCP6OptIAPDBasicInstantiation():
    assert raw(
        DHCP6OptIA_PD()) == b'\x00\x19\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DHCP6OptIA_PD - Instantiation with a list of different opts: IA Address and Status Code (optlen automatic computation) 
def test_DHCP6OptIAPDInstantiationwithalistofdifferentoptsIAAddressandStatusCodeoptlenautomaticcomputation():
    assert raw(DHCP6OptIA_PD(iaid=0x22222222, T1=0x33333333, T2=0x44444444,
                             iapdopt=[DHCP6OptIAAddress(),
                                      DHCP6OptStatusCode(statuscode=0xff,
                                                         statusmsg="Hello")])) == b'\x00\x19\x003""""3333DDDD\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\x00\x07\x00\xffHello'


# DHCP6OptNISServers - Basic Instantiation
def test_DHCP6OptNISServersBasicInstantiation():
    assert raw(DHCP6OptNISServers()) == b'\x00\x1b\x00\x00'


# DHCP6OptNISServers - Basic Dissection 
def test_DHCP6OptNISServersBasicDissection():
    a = DHCP6OptNISServers(b'\x00\x1b\x00\x00')
    assert a.optcode == 27 and a.optlen == 0 and a.nisservers == []


# DHCP6OptNISServers - Instantiation with specific values (1 address) 
def test_DHCP6OptNISServersInstantiationwithspecificvalues1address():
    assert raw(DHCP6OptNISServers(nisservers=[
        "2001:db8::1"])) == b'\x00\x1b\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


# DHCP6OptNISServers - Dissection with specific values (1 address) 
def test_DHCP6OptNISServersDissectionwithspecificvalues1address():
    a = DHCP6OptNISServers(
        b'\x00\x1b\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 27 and a.optlen == 16 and len(a.nisservers) == 1 and \
           a.nisservers[0] == "2001:db8::1"


# DHCP6OptNISServers - Instantiation with specific values (2 addresses) 
def test_DHCP6OptNISServersInstantiationwithspecificvalues2addresses():
    assert raw(DHCP6OptNISServers(nisservers=["2001:db8::1",
                                              "2001:db8::2"])) == b'\x00\x1b\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


# DHCP6OptNISServers - Dissection with specific values (2 addresses) 
def test_DHCP6OptNISServersDissectionwithspecificvalues2addresses():
    a = DHCP6OptNISServers(
        b'\x00\x1b\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 27 and a.optlen == 32 and len(a.nisservers) == 2 and \
           a.nisservers[0] == "2001:db8::1" and a.nisservers[1] == "2001:db8::2"


# DHCP6OptNISPServers - Basic Instantiation
def test_DHCP6OptNISPServersBasicInstantiation():
    assert raw(DHCP6OptNISPServers()) == b'\x00\x1c\x00\x00'


# DHCP6OptNISPServers - Basic Dissection 
def test_DHCP6OptNISPServersBasicDissection():
    a = DHCP6OptNISPServers(b'\x00\x1c\x00\x00')
    assert a.optcode == 28 and a.optlen == 0 and a.nispservers == []


# DHCP6OptNISPServers - Instantiation with specific values (1 address) 
def test_DHCP6OptNISPServersInstantiationwithspecificvalues1address():
    assert raw(DHCP6OptNISPServers(nispservers=[
        "2001:db8::1"])) == b'\x00\x1c\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


# DHCP6OptNISPServers - Dissection with specific values (1 address) 
def test_DHCP6OptNISPServersDissectionwithspecificvalues1address():
    a = DHCP6OptNISPServers(
        b'\x00\x1c\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 28 and a.optlen == 16 and len(a.nispservers) == 1 and \
           a.nispservers[0] == "2001:db8::1"


# DHCP6OptNISPServers - Instantiation with specific values (2 addresses) 
def test_DHCP6OptNISPServersInstantiationwithspecificvalues2addresses():
    assert raw(DHCP6OptNISPServers(nispservers=["2001:db8::1",
                                                "2001:db8::2"])) == b'\x00\x1c\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


# DHCP6OptNISPServers - Dissection with specific values (2 addresses) 
def test_DHCP6OptNISPServersDissectionwithspecificvalues2addresses():
    a = DHCP6OptNISPServers(
        b'\x00\x1c\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 28 and a.optlen == 32 and len(a.nispservers) == 2 and \
           a.nispservers[0] == "2001:db8::1" and a.nispservers[
               1] == "2001:db8::2"


# DHCP6OptNISDomain - Basic Instantiation
def test_DHCP6OptNISDomainBasicInstantiation():
    assert raw(DHCP6OptNISDomain()) == b'\x00\x1d\x00\x01\x00'


# DHCP6OptNISDomain - Basic Dissection 
def test_DHCP6OptNISDomainBasicDissection():
    a = DHCP6OptNISDomain(b'\x00\x1d\x00\x00')
    assert a.optcode == 29 and a.optlen == 0 and a.nisdomain == b"."


# DHCP6OptNISDomain - Instantiation with one domain name 
def test_DHCP6OptNISDomainInstantiationwithonedomainname():
    assert raw(DHCP6OptNISDomain(
        nisdomain="toto.example.org")) == b'\x00\x1d\x00\x12\x04toto\x07example\x03org\x00'


# DHCP6OptNISDomain - Dissection with one domain name 
def test_DHCP6OptNISDomainDissectionwithonedomainname():
    a = DHCP6OptNISDomain(b'\x00\x1d\x00\x11\x04toto\x07example\x03org\x00')
    assert a.optcode == 29 and a.optlen == 17 and a.nisdomain == b"toto.example.org."


# DHCP6OptNISDomain - Instantiation with one domain with trailing dot 
def test_DHCP6OptNISDomainInstantiationwithonedomainwithtrailingdot():
    assert raw(DHCP6OptNISDomain(
        nisdomain="toto.example.org.")) == b'\x00\x1d\x00\x12\x04toto\x07example\x03org\x00'


# DHCP6OptNISPDomain - Basic Instantiation
def test_DHCP6OptNISPDomainBasicInstantiation():
    assert raw(DHCP6OptNISPDomain()) == b'\x00\x1e\x00\x01\x00'


# DHCP6OptNISPDomain - Basic Dissection 
def test_DHCP6OptNISPDomainBasicDissection():
    a = DHCP6OptNISPDomain(b'\x00\x1e\x00\x00')
    assert a.optcode == 30 and a.optlen == 0 and a.nispdomain == b"."


# DHCP6OptNISPDomain - Instantiation with one domain name 
def test_DHCP6OptNISPDomainInstantiationwithonedomainname():
    assert raw(DHCP6OptNISPDomain(
        nispdomain="toto.example.org")) == b'\x00\x1e\x00\x12\x04toto\x07example\x03org\x00'


# DHCP6OptNISPDomain - Dissection with one domain name 
def test_DHCP6OptNISPDomainDissectionwithonedomainname():
    a = DHCP6OptNISPDomain(b'\x00\x1e\x00\x12\x04toto\x07example\x03org\x00')
    assert a.optcode == 30 and a.optlen == 18 and a.nispdomain == b"toto.example.org."


# DHCP6OptNISPDomain - Instantiation with one domain with trailing dot 
def test_DHCP6OptNISPDomainInstantiationwithonedomainwithtrailingdot():
    assert raw(DHCP6OptNISPDomain(
        nispdomain="toto.example.org.")) == b'\x00\x1e\x00\x12\x04toto\x07example\x03org\x00'


# DHCP6OptSNTPServers - Basic Instantiation
def test_DHCP6OptSNTPServersBasicInstantiation():
    assert raw(DHCP6OptSNTPServers()) == b'\x00\x1f\x00\x00'


# DHCP6OptSNTPServers - Basic Dissection 
def test_DHCP6OptSNTPServersBasicDissection():
    a = DHCP6OptSNTPServers(b'\x00\x1f\x00\x00')
    assert a.optcode == 31 and a.optlen == 0 and a.sntpservers == []


# DHCP6OptSNTPServers - Instantiation with specific values (1 address) 
def test_DHCP6OptSNTPServersInstantiationwithspecificvalues1address():
    assert raw(DHCP6OptSNTPServers(sntpservers=[
        "2001:db8::1"])) == b'\x00\x1f\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


# DHCP6OptSNTPServers - Dissection with specific values (1 address) 
def test_DHCP6OptSNTPServersDissectionwithspecificvalues1address():
    a = DHCP6OptSNTPServers(
        b'\x00\x1f\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 31 and a.optlen == 16 and len(a.sntpservers) == 1 and \
           a.sntpservers[0] == "2001:db8::1"


# DHCP6OptSNTPServers - Instantiation with specific values (2 addresses) 
def test_DHCP6OptSNTPServersInstantiationwithspecificvalues2addresses():
    assert raw(DHCP6OptSNTPServers(sntpservers=["2001:db8::1",
                                                "2001:db8::2"])) == b'\x00\x1f\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


# DHCP6OptSNTPServers - Dissection with specific values (2 addresses) 
def test_DHCP6OptSNTPServersDissectionwithspecificvalues2addresses():
    a = DHCP6OptSNTPServers(
        b'\x00\x1f\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 31 and a.optlen == 32 and len(a.sntpservers) == 2 and \
           a.sntpservers[0] == "2001:db8::1" and a.sntpservers[
               1] == "2001:db8::2"


# DHCP6OptInfoRefreshTime - Basic Instantiation
def test_DHCP6OptInfoRefreshTimeBasicInstantiation():
    assert raw(DHCP6OptInfoRefreshTime()) == b'\x00 \x00\x04\x00\x01Q\x80'


# DHCP6OptInfoRefreshTime - Basic Dissction 
def test_DHCP6OptInfoRefreshTimeBasicDissction():
    a = DHCP6OptInfoRefreshTime(b'\x00 \x00\x04\x00\x01Q\x80')
    assert a.optcode == 32 and a.optlen == 4 and a.reftime == 86400


# DHCP6OptInfoRefreshTime - Instantiation with specific values 
def test_DHCP6OptInfoRefreshTimeInstantiationwithspecificvalues():
    assert raw(DHCP6OptInfoRefreshTime(optlen=7,
                                       reftime=42)) == b'\x00 \x00\x07\x00\x00\x00*'


# DHCP6OptBCMCSServers - Basic Instantiation
def test_DHCP6OptBCMCSServersBasicInstantiation():
    assert raw(DHCP6OptBCMCSServers()) == b'\x00"\x00\x00'


# DHCP6OptBCMCSServers - Basic Dissection 
def test_DHCP6OptBCMCSServersBasicDissection():
    a = DHCP6OptBCMCSServers(b'\x00"\x00\x00')
    assert a.optcode == 34 and a.optlen == 0 and a.bcmcsservers == []


# DHCP6OptBCMCSServers - Instantiation with specific values (1 address) 
def test_DHCP6OptBCMCSServersInstantiationwithspecificvalues1address():
    assert raw(DHCP6OptBCMCSServers(bcmcsservers=[
        "2001:db8::1"])) == b'\x00"\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


# DHCP6OptBCMCSServers - Dissection with specific values (1 address) 
def test_DHCP6OptBCMCSServersDissectionwithspecificvalues1address():
    a = DHCP6OptBCMCSServers(
        b'\x00"\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 34 and a.optlen == 16 and len(a.bcmcsservers) == 1 and \
           a.bcmcsservers[0] == "2001:db8::1"


# DHCP6OptBCMCSServers - Instantiation with specific values (2 addresses) 
def test_DHCP6OptBCMCSServersInstantiationwithspecificvalues2addresses():
    assert raw(DHCP6OptBCMCSServers(bcmcsservers=["2001:db8::1",
                                                  "2001:db8::2"])) == b'\x00"\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


# DHCP6OptBCMCSServers - Dissection with specific values (2 addresses) 
def test_DHCP6OptBCMCSServersDissectionwithspecificvalues2addresses():
    a = DHCP6OptBCMCSServers(
        b'\x00"\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 34 and a.optlen == 32 and len(a.bcmcsservers) == 2 and \
           a.bcmcsservers[0] == "2001:db8::1" and a.bcmcsservers[
               1] == "2001:db8::2"


# DHCP6OptBCMCSDomains - Basic Instantiation
def test_DHCP6OptBCMCSDomainsBasicInstantiation():
    assert raw(DHCP6OptBCMCSDomains()) == b'\x00!\x00\x00'


# DHCP6OptBCMCSDomains - Basic Dissection 
def test_DHCP6OptBCMCSDomainsBasicDissection():
    a = DHCP6OptBCMCSDomains(b'\x00!\x00\x00')
    assert a.optcode == 33 and a.optlen == 0 and a.bcmcsdomains == []


# DHCP6OptBCMCSDomains - Instantiation with specific values (1 domain) 
def test_DHCP6OptBCMCSDomainsInstantiationwithspecificvalues1domain():
    assert raw(DHCP6OptBCMCSDomains(bcmcsdomains=[
        "toto.example.com."])) == b'\x00!\x00\x12\x04toto\x07example\x03com\x00'


# DHCP6OptBCMCSDomains - Dissection with specific values (1 domain) 
def test_DHCP6OptBCMCSDomainsDissectionwithspecificvalues1domain():
    a = DHCP6OptBCMCSDomains(b'\x00!\x00\x12\x04toto\x07example\x03com\x00')
    assert a.optcode == 33 and a.optlen == 18 and len(a.bcmcsdomains) == 1 and \
           a.bcmcsdomains[0] == "toto.example.com."


# DHCP6OptBCMCSDomains - Instantiation with specific values (2 domains) 
def test_DHCP6OptBCMCSDomainsInstantiationwithspecificvalues2domains():
    assert raw(DHCP6OptBCMCSDomains(bcmcsdomains=["toto.example.com.",
                                                  "titi.example.com."])) == b'\x00!\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00'


# DHCP6OptBCMCSDomains - Dissection with specific values (2 domains) 
def test_DHCP6OptBCMCSDomainsDissectionwithspecificvalues2domains():
    a = DHCP6OptBCMCSDomains(
        b'\x00!\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00')
    assert a.optcode == 33 and a.optlen == 36 and len(a.bcmcsdomains) == 2 and \
           a.bcmcsdomains[0] == "toto.example.com." and a.bcmcsdomains[
               1] == "titi.example.com."


# DHCP6OptRemoteID - Basic Instantiation
def test_DHCP6OptRemoteIDBasicInstantiation():
    assert raw(DHCP6OptRemoteID()) == b'\x00%\x00\x04\x00\x00\x00\x00'


# DHCP6OptRemoteID - Basic Dissection 
def test_DHCP6OptRemoteIDBasicDissection():
    a = DHCP6OptRemoteID(b'\x00%\x00\x04\x00\x00\x00\x00')
    assert a.optcode == 37 and a.optlen == 4 and a.enterprisenum == 0 and a.remoteid == b""


# DHCP6OptRemoteID - Instantiation with specific values 
def test_DHCP6OptRemoteIDInstantiationwithspecificvalues():
    assert raw(DHCP6OptRemoteID(enterprisenum=0xeeeeeeee,
                                remoteid="someid")) == b'\x00%\x00\n\xee\xee\xee\xeesomeid'


# DHCP6OptRemoteID - Dissection with specific values 
def test_DHCP6OptRemoteIDDissectionwithspecificvalues():
    a = DHCP6OptRemoteID(b'\x00%\x00\n\xee\xee\xee\xeesomeid')
    assert a.optcode == 37 and a.optlen == 10 and a.enterprisenum == 0xeeeeeeee and a.remoteid == b"someid"


# DHCP6OptSubscriberID - Basic Instantiation
def test_DHCP6OptSubscriberIDBasicInstantiation():
    assert raw(DHCP6OptSubscriberID()) == b'\x00&\x00\x00'


# DHCP6OptSubscriberID - Basic Dissection 
def test_DHCP6OptSubscriberIDBasicDissection():
    a = DHCP6OptSubscriberID(b'\x00&\x00\x00')
    assert a.optcode == 38 and a.optlen == 0 and a.subscriberid == b""


# DHCP6OptSubscriberID - Instantiation with specific values 
def test_DHCP6OptSubscriberIDInstantiationwithspecificvalues():
    assert raw(
        DHCP6OptSubscriberID(subscriberid="someid")) == b'\x00&\x00\x06someid'


# DHCP6OptSubscriberID - Dissection with specific values 
def test_DHCP6OptSubscriberIDDissectionwithspecificvalues():
    a = DHCP6OptSubscriberID(b'\x00&\x00\x06someid')
    assert a.optcode == 38 and a.optlen == 6 and a.subscriberid == b"someid"


# DHCP6OptClientFQDN - Basic Instantiation
def test_DHCP6OptClientFQDNBasicInstantiation():
    assert raw(DHCP6OptClientFQDN()) == b"\x00'\x00\x02\x00\x00"


# DHCP6OptClientFQDN - Basic Dissection 
def test_DHCP6OptClientFQDNBasicDissection():
    a = DHCP6OptClientFQDN(b"\x00'\x00\x01\x00")
    assert a.optcode == 39 and a.optlen == 1 and a.res == 0 and a.flags == 0 and a.fqdn == b"."


# DHCP6OptClientFQDN - Instantiation with various flags combinations 
def test_DHCP6OptClientFQDNInstantiationwithvariousflagscombinations():
    assert raw(
        DHCP6OptClientFQDN(flags="S")) == b"\x00'\x00\x02\x01\x00" and raw(
        DHCP6OptClientFQDN(flags="O")) == b"\x00'\x00\x02\x02\x00" and raw(
        DHCP6OptClientFQDN(flags="N")) == b"\x00'\x00\x02\x04\x00" and raw(
        DHCP6OptClientFQDN(flags="SON")) == b"\x00'\x00\x02\x07\x00" and raw(
        DHCP6OptClientFQDN(flags="ON")) == b"\x00'\x00\x02\x06\x00"


# DHCP6OptClientFQDN - Instantiation with one fqdn 
def test_DHCP6OptClientFQDNInstantiationwithonefqdn():
    assert raw(DHCP6OptClientFQDN(
        fqdn="toto.example.org")) == b"\x00'\x00\x13\x00\x04toto\x07example\x03org\x00"


# DHCP6OptClientFQDN - Dissection with one fqdn 
def test_DHCP6OptClientFQDNDissectionwithonefqdn():
    a = DHCP6OptClientFQDN(b"\x00'\x00\x12\x00\x04toto\x07example\x03org\x00")
    assert a.optcode == 39 and a.optlen == 18 and a.res == 0 and a.flags == 0 and a.fqdn == b"toto.example.org."


# DHCP6OptPanaAuthAgent - Basic Instantiation
def test_DHCP6OptPanaAuthAgentBasicInstantiation():
    assert raw(DHCP6OptPanaAuthAgent()) == b'\x00(\x00\x00'


# DHCP6OptPanaAuthAgent - Basic Dissection 
def test_DHCP6OptPanaAuthAgentBasicDissection():
    a = DHCP6OptPanaAuthAgent(b"\x00(\x00\x00")
    assert a.optcode == 40 and a.optlen == 0 and a.paaaddr == []


# DHCP6OptPanaAuthAgent - Instantiation with specific values (1 address) 
def test_DHCP6OptPanaAuthAgentInstantiationwithspecificvalues1address():
    assert raw(DHCP6OptPanaAuthAgent(paaaddr=[
        "2001:db8::1"])) == b'\x00(\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


# DHCP6OptPanaAuthAgent - Dissection with specific values (1 address) 
def test_DHCP6OptPanaAuthAgentDissectionwithspecificvalues1address():
    a = DHCP6OptPanaAuthAgent(
        b'\x00(\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 40 and a.optlen == 16 and len(a.paaaddr) == 1 and \
           a.paaaddr[0] == "2001:db8::1"


# DHCP6OptPanaAuthAgent - Instantiation with specific values (2 addresses) 
def test_DHCP6OptPanaAuthAgentInstantiationwithspecificvalues2addresses():
    assert raw(DHCP6OptPanaAuthAgent(paaaddr=["2001:db8::1",
                                              "2001:db8::2"])) == b'\x00(\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


# DHCP6OptPanaAuthAgent - Dissection with specific values (2 addresses) 
def test_DHCP6OptPanaAuthAgentDissectionwithspecificvalues2addresses():
    a = DHCP6OptPanaAuthAgent(
        b'\x00(\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 40 and a.optlen == 32 and len(a.paaaddr) == 2 and \
           a.paaaddr[0] == "2001:db8::1" and a.paaaddr[1] == "2001:db8::2"


# DHCP6OptNewPOSIXTimeZone - Basic Instantiation
def test_DHCP6OptNewPOSIXTimeZoneBasicInstantiation():
    assert raw(DHCP6OptNewPOSIXTimeZone()) == b'\x00)\x00\x00'


# DHCP6OptNewPOSIXTimeZone - Basic Dissection 
def test_DHCP6OptNewPOSIXTimeZoneBasicDissection():
    a = DHCP6OptNewPOSIXTimeZone(b'\x00)\x00\x00')
    assert a.optcode == 41 and a.optlen == 0 and a.optdata == b""


# DHCP6OptNewPOSIXTimeZone - Instantiation with specific values 
def test_DHCP6OptNewPOSIXTimeZoneInstantiationwithspecificvalues():
    assert raw(DHCP6OptNewPOSIXTimeZone(
        optdata="EST5EDT4,M3.2.0/02:00,M11.1.0/02:00")) == b'\x00)\x00#EST5EDT4,M3.2.0/02:00,M11.1.0/02:00'


# DHCP6OptNewPOSIXTimeZone - Dissection with specific values 
def test_DHCP6OptNewPOSIXTimeZoneDissectionwithspecificvalues():
    a = DHCP6OptNewPOSIXTimeZone(
        b'\x00)\x00#EST5EDT4,M3.2.0/02:00,M11.1.0/02:00')
    assert a.optcode == 41 and a.optlen == 35 and a.optdata == b"EST5EDT4,M3.2.0/02:00,M11.1.0/02:00"


# DHCP6OptNewTZDBTimeZone - Basic Instantiation
def test_DHCP6OptNewTZDBTimeZoneBasicInstantiation():
    assert raw(DHCP6OptNewTZDBTimeZone()) == b'\x00*\x00\x00'


# DHCP6OptNewTZDBTimeZone - Basic Dissection 
def test_DHCP6OptNewTZDBTimeZoneBasicDissection():
    a = DHCP6OptNewTZDBTimeZone(b'\x00*\x00\x00')
    assert a.optcode == 42 and a.optlen == 0 and a.optdata == b""


# DHCP6OptNewTZDBTimeZone - Instantiation with specific values 
def test_DHCP6OptNewTZDBTimeZoneInstantiationwithspecificvalues():
    assert raw(DHCP6OptNewTZDBTimeZone(
        optdata="Europe/Zurich")) == b'\x00*\x00\rEurope/Zurich'


# DHCP6OptNewTZDBTimeZone - Dissection with specific values 
def test_DHCP6OptNewTZDBTimeZoneDissectionwithspecificvalues():
    a = DHCP6OptNewTZDBTimeZone(b'\x00*\x00\rEurope/Zurich')
    assert a.optcode == 42 and a.optlen == 13 and a.optdata == b"Europe/Zurich"


# DHCP6OptRelayAgentERO - Basic Instantiation
def test_DHCP6OptRelayAgentEROBasicInstantiation():
    assert raw(DHCP6OptRelayAgentERO()) == b'\x00+\x00\x04\x00\x17\x00\x18'


# DHCP6OptRelayAgentERO - optlen field computation 
def test_DHCP6OptRelayAgentEROoptlenfieldcomputation():
    assert raw(DHCP6OptRelayAgentERO(reqopts=[1, 2, 3,
                                              4])) == b'\x00+\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04'


# DHCP6OptRelayAgentERO - instantiation with empty list 
def test_DHCP6OptRelayAgentEROinstantiationwithemptylist():
    assert raw(DHCP6OptRelayAgentERO(reqopts=[])) == b'\x00+\x00\x00'


# DHCP6OptRelayAgentERO - Basic dissection 
def test_DHCP6OptRelayAgentEROBasicdissection():
    a = DHCP6OptRelayAgentERO(b'\x00+\x00\x00')
    assert a.optcode == 43 and a.optlen == 0 and a.reqopts == [23, 24]


# DHCP6OptRelayAgentERO - Dissection with specific value 
def test_DHCP6OptRelayAgentERODissectionwithspecificvalue():
    a = DHCP6OptRelayAgentERO(b'\x00+\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04')
    assert a.optcode == 43 and a.optlen == 8 and a.reqopts == [1, 2, 3, 4]


# DHCP6OptLQClientLink - Basic Instantiation
def test_DHCP6OptLQClientLinkBasicInstantiation():
    assert raw(DHCP6OptLQClientLink()) == b'\x000\x00\x00'


# DHCP6OptLQClientLink - Basic Dissection 
def test_DHCP6OptLQClientLinkBasicDissection():
    a = DHCP6OptLQClientLink(b"\x000\x00\x00")
    assert a.optcode == 48 and a.optlen == 0 and a.linkaddress == []


# DHCP6OptLQClientLink - Instantiation with specific values (1 address) 
def test_DHCP6OptLQClientLinkInstantiationwithspecificvalues1address():
    assert raw(DHCP6OptLQClientLink(linkaddress=[
        "2001:db8::1"])) == b'\x000\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


# DHCP6OptLQClientLink - Dissection with specific values (1 address) 
def test_DHCP6OptLQClientLinkDissectionwithspecificvalues1address():
    a = DHCP6OptLQClientLink(
        b'\x000\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 48 and a.optlen == 16 and len(a.linkaddress) == 1 and \
           a.linkaddress[0] == "2001:db8::1"


# DHCP6OptLQClientLink - Instantiation with specific values (2 addresses) 
def test_DHCP6OptLQClientLinkInstantiationwithspecificvalues2addresses():
    assert raw(DHCP6OptLQClientLink(linkaddress=["2001:db8::1",
                                                 "2001:db8::2"])) == b'\x000\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


# DHCP6OptLQClientLink - Dissection with specific values (2 addresses) 
def test_DHCP6OptLQClientLinkDissectionwithspecificvalues2addresses():
    a = DHCP6OptLQClientLink(
        b'\x000\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 48 and a.optlen == 32 and len(a.linkaddress) == 2 and \
           a.linkaddress[0] == "2001:db8::1" and a.linkaddress[
               1] == "2001:db8::2"


# DHCP6OptBootFileUrl - Basic Instantiation
def test_DHCP6OptBootFileUrlBasicInstantiation():
    assert raw(DHCP6OptBootFileUrl()) == b'\x00;\x00\x00'


# DHCP6OptBootFileUrl - Basic Dissection 
def test_DHCP6OptBootFileUrlBasicDissection():
    a = DHCP6OptBootFileUrl(b'\x00;\x00\x00')
    assert a.optcode == 59 and a.optlen == 0 and a.optdata == b""


# DHCP6OptBootFileUrl - Instantiation with specific values 
def test_DHCP6OptBootFileUrlInstantiationwithspecificvalues():
    assert raw(DHCP6OptBootFileUrl(
        optdata="http://wp.pl/file")) == b'\x00;\x00\x11http://wp.pl/file'


# DHCP6OptBootFileUrl - Dissection with specific values 
def test_DHCP6OptBootFileUrlDissectionwithspecificvalues():
    a = DHCP6OptBootFileUrl(b'\x00;\x00\x11http://wp.pl/file')
    assert a.optcode == 59 and a.optlen == 17 and a.optdata == b"http://wp.pl/file"


# DHCP6OptClientArchType - Basic Instantiation
def test_DHCP6OptClientArchTypeBasicInstantiation():
    raw(DHCP6OptClientArchType())
    assert raw(DHCP6OptClientArchType()) == b'\x00=\x00\x00'


# DHCP6OptClientArchType - Basic Dissection 
def test_DHCP6OptClientArchTypeBasicDissection():
    a = DHCP6OptClientArchType(b'\x00=\x00\x00')
    assert a.optcode == 61 and a.optlen == 0 and a.archtypes == []


# DHCP6OptClientArchType - Instantiation with specific value as just int 
def test_DHCP6OptClientArchTypeInstantiationwithspecificvalueasjustint():
    assert raw(DHCP6OptClientArchType(archtypes=7)) == b'\x00=\x00\x02\x00\x07'


# DHCP6OptClientArchType - Instantiation with specific value as single item list of int 
def test_DHCP6OptClientArchTypeInstantiationwithspecificvalueassingleitemlistofint():
    assert raw(
        DHCP6OptClientArchType(archtypes=[7])) == b'\x00=\x00\x02\x00\x07'


# DHCP6OptClientArchType - Dissection with specific 1 value list 
def test_DHCP6OptClientArchTypeDissectionwithspecific1valuelist():
    a = DHCP6OptClientArchType(b'\x00=\x00\x02\x00\x07')
    assert a.optcode == 61 and a.optlen == 2 and a.archtypes == [7]


# DHCP6OptClientArchType - Instantiation with specific value as 2 item list of int 
def test_DHCP6OptClientArchTypeInstantiationwithspecificvalueas2itemlistofint():
    assert raw(DHCP6OptClientArchType(
        archtypes=[7, 9])) == b'\x00=\x00\x04\x00\x07\x00\x09'


# DHCP6OptClientArchType - Dissection with specific 2 values list 
def test_DHCP6OptClientArchTypeDissectionwithspecific2valueslist():
    a = DHCP6OptClientArchType(b'\x00=\x00\x04\x00\x07\x00\x09')
    assert a.optcode == 61 and a.optlen == 4 and a.archtypes == [7, 9]


# DHCP6OptClientNetworkInterId - Basic Instantiation
def test_DHCP6OptClientNetworkInterIdBasicInstantiation():
    raw(DHCP6OptClientNetworkInterId())
    assert raw(DHCP6OptClientNetworkInterId()) == b'\x00>\x00\x03\x00\x00\x00'


# DHCP6OptClientNetworkInterId - Basic Dissection 
def test_DHCP6OptClientNetworkInterIdBasicDissection():
    a = DHCP6OptClientNetworkInterId(b'\x00>\x00\x03\x00\x00\x00')
    assert a.optcode == 62 and a.optlen == 3 and a.iitype == 0 and a.iimajor == 0 and a.iiminor == 0


# DHCP6OptClientNetworkInterId - Instantiation with specific values 
def test_DHCP6OptClientNetworkInterIdInstantiationwithspecificvalues():
    assert raw(DHCP6OptClientNetworkInterId(iitype=1, iimajor=2,
                                            iiminor=3)) == b'\x00>\x00\x03\x01\x02\x03'


# DHCP6OptClientNetworkInterId - Dissection with specific values 
def test_DHCP6OptClientNetworkInterIdDissectionwithspecificvalues():
    a = DHCP6OptClientNetworkInterId(b'\x00>\x00\x03\x01\x02\x03')
    assert a.optcode == 62 and a.optlen == 3 and a.iitype == 1 and a.iimajor == 2 and a.iiminor == 3


# DHCP6OptERPDomain - Basic Instantiation
def test_DHCP6OptERPDomainBasicInstantiation():
    assert raw(DHCP6OptERPDomain()) == b'\x00A\x00\x00'


# DHCP6OptERPDomain - Basic Dissection 
def test_DHCP6OptERPDomainBasicDissection():
    a = DHCP6OptERPDomain(b'\x00A\x00\x00')
    assert a.optcode == 65 and a.optlen == 0 and a.erpdomain == []


# DHCP6OptERPDomain - Instantiation with specific values (1 domain) 
def test_DHCP6OptERPDomainInstantiationwithspecificvalues1domain():
    assert raw(DHCP6OptERPDomain(erpdomain=[
        "toto.example.com."])) == b'\x00A\x00\x12\x04toto\x07example\x03com\x00'


# DHCP6OptERPDomain - Dissection with specific values (1 domain) 
def test_DHCP6OptERPDomainDissectionwithspecificvalues1domain():
    a = DHCP6OptERPDomain(b'\x00A\x00\x12\x04toto\x07example\x03com\x00')
    assert a.optcode == 65 and a.optlen == 18 and len(a.erpdomain) == 1 and \
           a.erpdomain[0] == "toto.example.com."


# DHCP6OptERPDomain - Instantiation with specific values (2 domains) 
def test_DHCP6OptERPDomainInstantiationwithspecificvalues2domains():
    assert raw(DHCP6OptERPDomain(erpdomain=["toto.example.com.",
                                            "titi.example.com."])) == b'\x00A\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00'


# DHCP6OptERPDomain - Dissection with specific values (2 domains) 
def test_DHCP6OptERPDomainDissectionwithspecificvalues2domains():
    a = DHCP6OptERPDomain(
        b'\x00A\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00')
    assert a.optcode == 65 and a.optlen == 36 and len(a.erpdomain) == 2 and \
           a.erpdomain[0] == "toto.example.com." and a.erpdomain[
               1] == "titi.example.com."


# DHCP6OptRelaySuppliedOpt - Basic Instantiation
def test_DHCP6OptRelaySuppliedOptBasicInstantiation():
    assert raw(DHCP6OptRelaySuppliedOpt()) == b'\x00B\x00\x00'


# DHCP6OptRelaySuppliedOpt - Basic Dissection 
def test_DHCP6OptRelaySuppliedOptBasicDissection():
    a = DHCP6OptRelaySuppliedOpt(b'\x00B\x00\x00')
    assert a.optcode == 66 and a.optlen == 0 and a.relaysupplied == []


# DHCP6OptRelaySuppliedOpt - Instantiation with specific values 
def test_DHCP6OptRelaySuppliedOptInstantiationwithspecificvalues():
    assert raw(DHCP6OptRelaySuppliedOpt(relaysupplied=DHCP6OptERPDomain(
        erpdomain=[
            "toto.example.com."]))) == b'\x00B\x00\x16\x00A\x00\x12\x04toto\x07example\x03com\x00'


# DHCP6OptRelaySuppliedOpt - Dissection with specific values 
def test_DHCP6OptRelaySuppliedOptDissectionwithspecificvalues():
    a = DHCP6OptRelaySuppliedOpt(
        b'\x00B\x00\x16\x00A\x00\x12\x04toto\x07example\x03com\x00')
    assert a.optcode == 66 and a.optlen == 22 and len(
        a.relaysupplied) == 1 and isinstance(a.relaysupplied[0],
                                             DHCP6OptERPDomain) and \
           a.relaysupplied[0].erpdomain[0] == "toto.example.com."


# Basic build & dissect
def test_Basicbuilddissect():
    s = raw(DHCP6OptClientLinkLayerAddr())
    assert (s == b"\x00O\x00\x08\x00\x01\x00\x00\x00\x00\x00\x00")
    p = DHCP6OptClientLinkLayerAddr(s)
    assert (p.clladdr == "00:00:00:00:00:00")
    r = b"\x00O\x00\x08\x00\x01\x00\x01\x02\x03\x04\x05"
    p = DHCP6OptClientLinkLayerAddr(r)
    assert (p.clladdr == "00:01:02:03:04:05")


# Basic build & dissect
def test_Basicbuilddissect1():
    s = raw(DHCP6OptVSS())
    assert (s == b"\x00D\x00\x01\xff")
    p = DHCP6OptVSS(s)
    assert (p.type == 255)


# DHCP6_Solicit - Basic Instantiation
def test_DHCP6SolicitBasicInstantiation():
    assert raw(DHCP6_Solicit()) == b'\x01\x00\x00\x00'


# DHCP6_Solicit - Basic Dissection 
def test_DHCP6SolicitBasicDissection():
    a = DHCP6_Solicit(b'\x01\x00\x00\x00')
    assert a.msgtype == 1 and a.trid == 0


# DHCP6_Solicit - Basic test of DHCP6_solicit.hashret() 
def test_DHCP6SolicitBasictestofDHCP6solicithashret():
    assert DHCP6_Solicit().hashret() == b'\x00\x00\x00'


# DHCP6_Solicit - Test of DHCP6_solicit.hashret() with specific values 
def test_DHCP6SolicitTestofDHCP6solicithashretwithspecificvalues():
    assert DHCP6_Solicit(trid=0xbbccdd).hashret() == b'\xbb\xcc\xdd'


# DHCP6_Solicit - UDP ports overload 
def test_DHCP6SolicitUDPportsoverload():
    a = UDP() / DHCP6_Solicit()
    assert a.sport == 546 and a.dport == 547


# DHCP6_Solicit - Dispatch based on UDP port 
def test_DHCP6SolicitDispatchbasedonUDPport():
    a = UDP(raw(UDP() / DHCP6_Solicit()))
    isinstance(a.payload, DHCP6_Solicit)


# DHCP6_Advertise - Basic Instantiation
def test_DHCP6AdvertiseBasicInstantiation():
    assert raw(DHCP6_Advertise()) == b'\x02\x00\x00\x00'


# DHCP6_Advertise - Basic test of DHCP6_solicit.hashret() 
def test_DHCP6AdvertiseBasictestofDHCP6solicithashret():
    assert DHCP6_Advertise().hashret() == b'\x00\x00\x00'


# DHCP6_Advertise - Test of DHCP6_Advertise.hashret() with specific values 
def test_DHCP6AdvertiseTestofDHCP6Advertisehashretwithspecificvalues():
    assert DHCP6_Advertise(trid=0xbbccdd).hashret() == b'\xbb\xcc\xdd'


# DHCP6_Advertise - Basic test of answers() with solicit message 
def test_DHCP6AdvertiseBasictestofanswerswithsolicitmessage():
    a = DHCP6_Solicit()
    b = DHCP6_Advertise()
    assert a > b


# DHCP6_Advertise - Test of answers() with solicit message 
def test_DHCP6AdvertiseTestofanswerswithsolicitmessage():
    a = DHCP6_Solicit(trid=0xbbccdd)
    b = DHCP6_Advertise(trid=0xbbccdd)
    assert a > b


# DHCP6_Advertise - UDP ports overload 
def test_DHCP6AdvertiseUDPportsoverload():
    a = UDP() / DHCP6_Advertise()
    assert a.sport == 547 and a.dport == 546


# DHCP6_Request - Basic Instantiation
def test_DHCP6RequestBasicInstantiation():
    assert raw(DHCP6_Request()) == b'\x03\x00\x00\x00'


# DHCP6_Request - Basic Dissection 
def test_DHCP6RequestBasicDissection():
    a = DHCP6_Request(b'\x03\x00\x00\x00')
    assert a.msgtype == 3 and a.trid == 0


# DHCP6_Request - UDP ports overload 
def test_DHCP6RequestUDPportsoverload():
    a = UDP() / DHCP6_Request()
    assert a.sport == 546 and a.dport == 547


# DHCP6_Confirm - Basic Instantiation
def test_DHCP6ConfirmBasicInstantiation():
    assert raw(DHCP6_Confirm()) == b'\x04\x00\x00\x00'


# DHCP6_Confirm - Basic Dissection 
def test_DHCP6ConfirmBasicDissection():
    a = DHCP6_Confirm(b'\x04\x00\x00\x00')
    assert a.msgtype == 4 and a.trid == 0


# DHCP6_Confirm - UDP ports overload 
def test_DHCP6ConfirmUDPportsoverload():
    a = UDP() / DHCP6_Confirm()
    assert a.sport == 546 and a.dport == 547


# DHCP6_Renew - Basic Instantiation
def test_DHCP6RenewBasicInstantiation():
    assert raw(DHCP6_Renew()) == b'\x05\x00\x00\x00'


# DHCP6_Renew - Basic Dissection 
def test_DHCP6RenewBasicDissection():
    a = DHCP6_Renew(b'\x05\x00\x00\x00')
    assert a.msgtype == 5 and a.trid == 0


# DHCP6_Renew - UDP ports overload 
def test_DHCP6RenewUDPportsoverload():
    a = UDP() / DHCP6_Renew()
    assert a.sport == 546 and a.dport == 547


# DHCP6_Rebind - Basic Instantiation
def test_DHCP6RebindBasicInstantiation():
    assert raw(DHCP6_Rebind()) == b'\x06\x00\x00\x00'


# DHCP6_Rebind - Basic Dissection 
def test_DHCP6RebindBasicDissection():
    a = DHCP6_Rebind(b'\x06\x00\x00\x00')
    assert a.msgtype == 6 and a.trid == 0


# DHCP6_Rebind - UDP ports overload 
def test_DHCP6RebindUDPportsoverload():
    a = UDP() / DHCP6_Rebind()
    assert a.sport == 546 and a.dport == 547


# DHCP6_Reply - Basic Instantiation
def test_DHCP6ReplyBasicInstantiation():
    assert raw(DHCP6_Reply()) == b'\x07\x00\x00\x00'


# DHCP6_Reply - Basic Dissection 
def test_DHCP6ReplyBasicDissection():
    a = DHCP6_Reply(b'\x07\x00\x00\x00')
    assert a.msgtype == 7 and a.trid == 0


# DHCP6_Reply - UDP ports overload 
def test_DHCP6ReplyUDPportsoverload():
    a = UDP() / DHCP6_Reply()
    assert a.sport == 547 and a.dport == 546


# DHCP6_Reply - Answers 
def test_DHCP6ReplyAnswers():
    assert not DHCP6_Reply(trid=0).answers(DHCP6_Request(trid=1))
    assert DHCP6_Reply(trid=1).answers(DHCP6_Request(trid=1))


# DHCP6_Release - Basic Instantiation
def test_DHCP6ReleaseBasicInstantiation():
    assert raw(DHCP6_Release()) == b'\x08\x00\x00\x00'


# DHCP6_Release - Basic Dissection 
def test_DHCP6ReleaseBasicDissection():
    a = DHCP6_Release(b'\x08\x00\x00\x00')
    assert a.msgtype == 8 and a.trid == 0


# DHCP6_Release - UDP ports overload 
def test_DHCP6ReleaseUDPportsoverload():
    a = UDP() / DHCP6_Release()
    assert a.sport == 546 and a.dport == 547


# DHCP6_Decline - Basic Instantiation
def test_DHCP6DeclineBasicInstantiation():
    assert raw(DHCP6_Decline()) == b'\x09\x00\x00\x00'


# DHCP6_Confirm - Basic Dissection 
def test_DHCP6ConfirmBasicDissection1():
    a = DHCP6_Confirm(b'\x09\x00\x00\x00')
    assert a.msgtype == 9 and a.trid == 0


# DHCP6_Decline - UDP ports overload 
def test_DHCP6DeclineUDPportsoverload():
    a = UDP() / DHCP6_Decline()
    assert a.sport == 546 and a.dport == 547


# DHCP6_Reconf - Basic Instantiation
def test_DHCP6ReconfBasicInstantiation():
    assert raw(DHCP6_Reconf()) == b'\x0A\x00\x00\x00'


# DHCP6_Reconf - Basic Dissection 
def test_DHCP6ReconfBasicDissection():
    a = DHCP6_Reconf(b'\x0A\x00\x00\x00')
    assert a.msgtype == 10 and a.trid == 0


# DHCP6_Reconf - UDP ports overload 
def test_DHCP6ReconfUDPportsoverload():
    a = UDP() / DHCP6_Reconf()
    assert a.sport == 547 and a.dport == 546


# DHCP6_InfoRequest - Basic Instantiation
def test_DHCP6InfoRequestBasicInstantiation():
    assert raw(DHCP6_InfoRequest()) == b'\x0B\x00\x00\x00'


# DHCP6_InfoRequest - Basic Dissection 
def test_DHCP6InfoRequestBasicDissection():
    a = DHCP6_InfoRequest(b'\x0B\x00\x00\x00')
    assert a.msgtype == 11 and a.trid == 0


# DHCP6_InfoRequest - UDP ports overload 
def test_DHCP6InfoRequestUDPportsoverload():
    a = UDP() / DHCP6_InfoRequest()
    assert a.sport == 546 and a.dport == 547


# DHCP6_RelayForward - Basic Instantiation
def test_DHCP6RelayForwardBasicInstantiation():
    assert raw(
        DHCP6_RelayForward()) == b'\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DHCP6_RelayForward - Basic Dissection 
def test_DHCP6RelayForwardBasicDissection():
    a = DHCP6_RelayForward(
        b'\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.msgtype == 12 and a.hopcount == 0 and a.linkaddr == "::" and a.peeraddr == "::"


# DHCP6_RelayForward - Dissection with options 
def test_DHCP6RelayForwardDissectionwithoptions():
    a = DHCP6_RelayForward(
        b'\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x04\x03\x01\x00\x00')
    assert a.msgtype == 12 and DHCP6OptRelayMsg in a and isinstance(a.message,
                                                                    DHCP6_Request)


# DHCP6_RelayForward - Advanced dissection 
def test_DHCP6RelayForwardAdvanceddissection():
    s = b'`\x00\x00\x00\x002\x11@\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x02#\x02#\x002\xf0\xaf\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x04\x01\x00\x00\x00'
    p = IPv6(s)
    assert DHCP6OptRelayMsg in p and isinstance(p.message, DHCP6_Solicit)


# DHCP6OptRelayMsg - Basic Instantiation
def test_DHCP6OptRelayMsgBasicInstantiation():
    assert raw(DHCP6OptRelayMsg(optcode=37)) == b'\x00%\x00\x04\x00\x00\x00\x00'


# DHCP6OptRelayMsg - Basic Dissection 
def test_DHCP6OptRelayMsgBasicDissection():
    a = DHCP6OptRelayMsg(b'\x00\r\x00\x00')
    assert a.optcode == 13 and a.optlen == 0 and isinstance(a.message, DHCP6)


# DHCP6OptRelayMsg - Embedded DHCP6 packet Instantiation 
def test_DHCP6OptRelayMsgEmbeddedDHCP6packetInstantiation():
    assert raw(DHCP6OptRelayMsg(
        message=DHCP6_Solicit())) == b'\x00\t\x00\x04\x01\x00\x00\x00'


# DHCP6OptRelayMsg - Embedded DHCP6 packet Dissection 
def test_DHCP6OptRelayMsgEmbeddedDHCP6packetDissection():
    p = DHCP6OptRelayMsg(b'\x00\t\x00\x04\x01\x00\x00\x00')
    assert isinstance(p.message, DHCP6_Solicit)


# DHCP6_RelayReply - Basic Instantiation
def test_DHCP6RelayReplyBasicInstantiation():
    assert raw(
        DHCP6_RelayReply()) == b'\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# DHCP6_RelayReply - Basic Dissection 
def test_DHCP6RelayReplyBasicDissection():
    a = DHCP6_RelayReply(
        b'\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.msgtype == 13 and a.hopcount == 0 and a.linkaddr == "::" and a.peeraddr == "::"
