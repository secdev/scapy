import pytest
from scapy.all import *


def test_DUIDLLTbasicinstantiation():
    """
    DUID_LLT basic instantiation
    """
    a = DUID_LLT()
    assert a is not None


def test_DUIDLLTbasicbuild():
    """
    DUID_LLT basic build
    """
    assert raw(
        DUID_LLT()) == b'\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DUIDLLTbuildwithspecificvalues():
    """
    DUID_LLT build with specific values 
    """
    assert raw(DUID_LLT(lladdr="ff:ff:ff:ff:ff:ff", timeval=0x11111111,
                        hwtype=0x2222)) == b'\x00\x01""\x11\x11\x11\x11\xff\xff\xff\xff\xff\xff'


def test_DUIDLLTbasicdissection():
    """
    DUID_LLT basic dissection 
    """
    a = DUID_LLT(raw(DUID_LLT()))
    assert a.type == 1 and a.hwtype == 1 and a.timeval == 0 and a.lladdr == "00:00:00:00:00:00"


def test_DUIDLLTdissectionwithspecificvalues():
    """
    DUID_LLT dissection with specific values 
    """
    a = DUID_LLT(b'\x00\x01""\x11\x11\x11\x11\xff\xff\xff\xff\xff\xff')
    assert a.type == 1 and a.hwtype == 0x2222 and a.timeval == 0x11111111 and a.lladdr == "ff:ff:ff:ff:ff:ff"


def test_DUIDENbasicinstantiation():
    """
    DUID_EN basic instantiation
    """
    a = DUID_EN()
    assert a is not None


def test_DUIDENbasicbuild():
    """
    DUID_EN basic build
    """
    assert raw(DUID_EN()) == b'\x00\x02\x00\x00\x017'


def test_DUIDENbuildwithspecificvalues():
    """
    DUID_EN build with specific values 
    """
    assert raw(DUID_EN(enterprisenum=0x11111111,
                       id="iamastring")) == b'\x00\x02\x11\x11\x11\x11iamastring'


def test_DUIDENbasicdissection():
    """
    DUID_EN basic dissection 
    """
    a = DUID_EN(b'\x00\x02\x00\x00\x017')
    assert a.type == 2 and a.enterprisenum == 311


def test_DUIDENdissectionwithspecificvalues():
    """
    DUID_EN dissection with specific values 
    """
    a = DUID_EN(b'\x00\x02\x11\x11\x11\x11iamarawing')
    assert a.type == 2 and a.enterprisenum == 0x11111111 and a.id == b"iamarawing"


def test_DUIDLLbasicinstantiation():
    """
    DUID_LL basic instantiation
    """
    a = DUID_LL()
    assert a is not None


def test_DUIDLLbasicbuild():
    """
    DUID_LL basic build
    """
    assert raw(DUID_LL()) == b'\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00'


def test_DUIDLLbuildwithspecificvalues():
    """
    DUID_LL build with specific values 
    """
    assert raw(DUID_LL(hwtype=1,
                       lladdr="ff:ff:ff:ff:ff:ff")) == b'\x00\x03\x00\x01\xff\xff\xff\xff\xff\xff'


def test_DUIDLLbasicdissection():
    """
    DUID_LL basic dissection 
    """
    a = DUID_LL(raw(DUID_LL()))
    assert a.type == 3 and a.hwtype == 1 and a.lladdr == "00:00:00:00:00:00"


def test_DUIDLLwithspecificvalues():
    """
    DUID_LL with specific values 
    """
    a = DUID_LL(b'\x00\x03\x00\x01\xff\xff\xff\xff\xff\xff')
    assert a.hwtype == 1 and a.lladdr == "ff:ff:ff:ff:ff:ff"


def test_DUIDUUIDbasicinstantiation():
    """
    DUID_UUID basic instantiation
    """
    a = DUID_UUID()
    assert a is not None


def test_DUIDUUIDbasicbuild():
    """
    DUID_UUID basic build
    """
    assert raw(DUID_UUID()) == b"\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"


def test_DUIDUUIDbuildwithspecificvalues():
    """
    DUID_UUID build with specific values 
    """
    assert raw(DUID_UUID(uuid="272adcca-138c-4e8d-b3f4-634e953128cf")) == \
           b"\x00\x04'*\xdc\xca\x13\x8cN\x8d\xb3\xf4cN\x951(\xcf"


def test_DUIDUUIDbasicdissection():
    """
    DUID_UUID basic dissection 
    """
    a = DUID_UUID(raw(DUID_UUID()))
    assert a.type == 4 and str(a.uuid) == "00000000-0000-0000-0000-000000000000"


def test_DUIDUUIDwithspecificvalues():
    """
    DUID_UUID with specific values 
    """
    a = DUID_UUID(b"\x00\x04'*\xdc\xca\x13\x8cN\x8d\xb3\xf4cN\x951(\xcf")
    assert a.type == 4 and str(a.uuid) == "272adcca-138c-4e8d-b3f4-634e953128cf"


def test_DHCP6OptUnknownbasicinstantiation():
    """
    DHCP6 Opt Unknown basic instantiation
    """
    a = DHCP6OptUnknown()
    assert a is not None


def test_DHCP6OptUnknownbasicbuilddefaultvalues():
    """
    DHCP6 Opt Unknown basic build (default values)
    """
    assert raw(DHCP6OptUnknown()) == b'\x00\x00\x00\x00'


def test_DHCP6OptUnknownlencomputationtest():
    """
    DHCP6 Opt Unknown - len computation test 
    """
    assert raw(DHCP6OptUnknown(data="shouldbe9")) == b'\x00\x00\x00\tshouldbe9'


def test_DHCP6OptClientIdbasicinstantiation():
    """
    DHCP6OptClientId basic instantiation
    """
    a = DHCP6OptClientId()
    assert a is not None


def test_DHCP6OptClientIdbasicbuild():
    """
    DHCP6OptClientId basic build 
    """
    assert raw(DHCP6OptClientId()) == b'\x00\x01\x00\x00'


def test_DHCP6OptClientIdinstantiationwithspecificvalues():
    """
    DHCP6OptClientId instantiation with specific values 
    """
    assert raw(DHCP6OptClientId(duid="toto")) == b'\x00\x01\x00\x04toto'


def test_DHCP6OptClientIdinstantiationwithDUIDLL():
    """
    DHCP6OptClientId instantiation with DUID_LL 
    """
    assert raw(DHCP6OptClientId(
        duid=DUID_LL())) == b'\x00\x01\x00\n\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00'


def test_DHCP6OptClientIdinstantiationwithDUIDLLT():
    """
    DHCP6OptClientId instantiation with DUID_LLT 
    """
    assert raw(DHCP6OptClientId(
        duid=DUID_LLT())) == b'\x00\x01\x00\x0e\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DHCP6OptClientIdinstantiationwithDUIDEN():
    """
    DHCP6OptClientId instantiation with DUID_EN 
    """
    assert raw(DHCP6OptClientId(
        duid=DUID_EN())) == b'\x00\x01\x00\x06\x00\x02\x00\x00\x017'


def test_DHCP6OptClientIdinstantiationwithspecifiedlength():
    """
    DHCP6OptClientId instantiation with specified length 
    """
    assert raw(DHCP6OptClientId(optlen=80,
                                duid="somestring")) == b'\x00\x01\x00Psomestring'


def test_DHCP6OptClientIdbasicdissection():
    """
    DHCP6OptClientId basic dissection 
    """
    a = DHCP6OptClientId(b'\x00\x01\x00\x00')
    assert a.optcode == 1 and a.optlen == 0


def test_DHCP6OptClientIdinstantiationwithspecifiedlength1():
    """
    DHCP6OptClientId instantiation with specified length 
    """
    assert raw(DHCP6OptClientId(optlen=80,
                                duid="somestring")) == b'\x00\x01\x00Psomestring'


def test_DHCP6OptClientIdbasicdissection1():
    """
    DHCP6OptClientId basic dissection 
    """
    a = DHCP6OptClientId(b'\x00\x01\x00\x00')
    assert a.optcode == 1 and a.optlen == 0


def test_DHCP6OptClientIddissectionwithspecificduidvalue():
    """
    DHCP6OptClientId dissection with specific duid value 
    """
    a = DHCP6OptClientId(b'\x00\x01\x00\x04somerawing')
    assert a.optcode == 1 and a.optlen == 4 and isinstance(a.duid,
                                                           Raw) and a.duid.load == b'some' and isinstance(
        a.payload, DHCP6OptUnknown)


def test_DHCP6OptClientIddissectionwithspecificDUIDLLasduidvalue():
    """
    DHCP6OptClientId dissection with specific DUID_LL as duid value 
    """
    a = DHCP6OptClientId(
        b'\x00\x01\x00\n\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 1 and a.optlen == 10 and isinstance(a.duid,
                                                            DUID_LL) and a.duid.type == 3 and a.duid.hwtype == 1 and a.duid.lladdr == "00:00:00:00:00:00"


def test_DHCP6OptClientIddissectionwithspecificDUIDLLTasduidvalue():
    """
    DHCP6OptClientId dissection with specific DUID_LLT as duid value 
    """
    a = DHCP6OptClientId(
        b'\x00\x01\x00\x0e\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 1 and a.optlen == 14 and isinstance(a.duid,
                                                            DUID_LLT) and a.duid.type == 1 and a.duid.hwtype == 1 and a.duid.timeval == 0 and a.duid.lladdr == "00:00:00:00:00:00"


def test_DHCP6OptClientIddissectionwithspecificDUIDENasduidvalue():
    """
    DHCP6OptClientId dissection with specific DUID_EN as duid value 
    """
    a = DHCP6OptClientId(b'\x00\x01\x00\x06\x00\x02\x00\x00\x017')
    assert a.optcode == 1 and a.optlen == 6 and isinstance(a.duid,
                                                           DUID_EN) and a.duid.type == 2 and a.duid.enterprisenum == 311 and a.duid.id == b""


def test_DHCP6OptServerIdbasicinstantiation():
    """
    DHCP6OptServerId basic instantiation
    """
    a = DHCP6OptServerId()
    assert a is not None


def test_DHCP6OptServerIdbasicbuild():
    """
    DHCP6OptServerId basic build
    """
    assert raw(DHCP6OptServerId()) == b'\x00\x02\x00\x00'


def test_DHCP6OptServerIdbasicbuildwithspecificvalues():
    """
    DHCP6OptServerId basic build with specific values 
    """
    assert raw(DHCP6OptServerId(duid="toto")) == b'\x00\x02\x00\x04toto'


def test_DHCP6OptServerIdinstantiationwithDUIDLL():
    """
    DHCP6OptServerId instantiation with DUID_LL 
    """
    assert raw(DHCP6OptServerId(
        duid=DUID_LL())) == b'\x00\x02\x00\n\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00'


def test_DHCP6OptServerIdinstantiationwithDUIDLLT():
    """
    DHCP6OptServerId instantiation with DUID_LLT 
    """
    assert raw(DHCP6OptServerId(
        duid=DUID_LLT())) == b'\x00\x02\x00\x0e\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DHCP6OptServerIdinstantiationwithDUIDEN():
    """
    DHCP6OptServerId instantiation with DUID_EN 
    """
    assert raw(DHCP6OptServerId(
        duid=DUID_EN())) == b'\x00\x02\x00\x06\x00\x02\x00\x00\x017'


def test_DHCP6OptServerIdinstantiationwithspecifiedlength():
    """
    DHCP6OptServerId instantiation with specified length 
    """
    assert raw(DHCP6OptServerId(optlen=80,
                                duid="somestring")) == b'\x00\x02\x00Psomestring'


def test_DHCP6OptServerIdbasicdissection():
    """
    DHCP6OptServerId basic dissection 
    """
    a = DHCP6OptServerId(b'\x00\x02\x00\x00')
    assert a.optcode == 2 and a.optlen == 0


def test_DHCP6OptServerIddissectionwithspecificduidvalue():
    """
    DHCP6OptServerId dissection with specific duid value 
    """
    a = DHCP6OptServerId(b'\x00\x02\x00\x04somerawing')
    assert a.optcode == 2 and a.optlen == 4 and isinstance(a.duid,
                                                           Raw) and a.duid.load == b'some' and isinstance(
        a.payload, DHCP6OptUnknown)


def test_DHCP6OptServerIddissectionwithspecificDUIDLLasduidvalue():
    """
    DHCP6OptServerId dissection with specific DUID_LL as duid value 
    """
    a = DHCP6OptServerId(
        b'\x00\x02\x00\n\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 2 and a.optlen == 10 and isinstance(a.duid,
                                                            DUID_LL) and a.duid.type == 3 and a.duid.hwtype == 1 and a.duid.lladdr == "00:00:00:00:00:00"


def test_DHCP6OptServerIddissectionwithspecificDUIDLLTasduidvalue():
    """
    DHCP6OptServerId dissection with specific DUID_LLT as duid value 
    """
    a = DHCP6OptServerId(
        b'\x00\x02\x00\x0e\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 2 and a.optlen == 14 and isinstance(a.duid,
                                                            DUID_LLT) and a.duid.type == 1 and a.duid.hwtype == 1 and a.duid.timeval == 0 and a.duid.lladdr == "00:00:00:00:00:00"


def test_DHCP6OptServerIddissectionwithspecificDUIDENasduidvalue():
    """
    DHCP6OptServerId dissection with specific DUID_EN as duid value 
    """
    a = DHCP6OptServerId(b'\x00\x02\x00\x06\x00\x02\x00\x00\x017')
    assert a.optcode == 2 and a.optlen == 6 and isinstance(a.duid,
                                                           DUID_EN) and a.duid.type == 2 and a.duid.enterprisenum == 311 and a.duid.id == b""


def test_DHCP6OptIAAddressBasicInstantiation():
    """
    DHCP6OptIAAddress - Basic Instantiation
    """
    assert raw(
        DHCP6OptIAAddress()) == b'\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DHCP6OptIAAddressBasicDissection():
    """
    DHCP6OptIAAddress - Basic Dissection 
    """
    a = DHCP6OptIAAddress(
        b'\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 5 and a.optlen == 24 and a.addr == "::" and a.preflft == 0 and a.validlft == 0 and a.iaaddropts == []


def test_DHCP6OptIAAddressInstantiationwithspecificvalues():
    """
    DHCP6OptIAAddress - Instantiation with specific values 
    """
    assert raw(DHCP6OptIAAddress(optlen=0x1111, addr="2222:3333::5555",
                                 preflft=0x66666666, validlft=0x77777777,
                                 iaaddropts="somestring")) == b'\x00\x05\x11\x11""33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00UUffffwwwwsomestring'


def test_DHCP6OptIAAddressInstantiationwithspecificvaluesdefaultoptlencomputation():
    """
    DHCP6OptIAAddress - Instantiation with specific values (default optlen computation) 
    """
    assert raw(DHCP6OptIAAddress(addr="2222:3333::5555", preflft=0x66666666,
                                 validlft=0x77777777,
                                 iaaddropts="somestring")) == b'\x00\x05\x00"""33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00UUffffwwwwsomestring'


def test_DHCP6OptIAAddressDissectionwithspecificvalues():
    """
    DHCP6OptIAAddress - Dissection with specific values 
    """
    a = DHCP6OptIAAddress(
        b'\x00\x05\x00"""33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00UUffffwwwwsomerawing')
    assert a.optcode == 5 and a.optlen == 34 and a.addr == "2222:3333::5555" and a.preflft == 0x66666666 and a.validlft == 0x77777777 and \
           a.iaaddropts[0].load == b"somerawing"


def test_DHCP6OptIANABasicInstantiation():
    """
    DHCP6OptIA_NA - Basic Instantiation
    """
    assert raw(
        DHCP6OptIA_NA()) == b'\x00\x03\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DHCP6OptIANABasicDissection():
    """
    DHCP6OptIA_NA - Basic Dissection 
    """
    a = DHCP6OptIA_NA(
        b'\x00\x03\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 3 and a.optlen == 12 and a.iaid == 0 and a.T1 == 0 and a.T2 == 0 and a.ianaopts == []


def test_DHCP6OptIANAInstantiationwithspecificvalueskeepautomaticlengthcomputation():
    """
    DHCP6OptIA_NA - Instantiation with specific values (keep automatic length computation) 
    """
    assert raw(DHCP6OptIA_NA(iaid=0x22222222, T1=0x33333333,
                             T2=0x44444444)) == b'\x00\x03\x00\x0c""""3333DDDD'


def test_DHCP6OptIANAInstantiationwithspecificvaluesforcedoptlen():
    """
    DHCP6OptIA_NA - Instantiation with specific values (forced optlen) 
    """
    assert raw(DHCP6OptIA_NA(optlen=0x1111, iaid=0x22222222, T1=0x33333333,
                             T2=0x44444444)) == b'\x00\x03\x11\x11""""3333DDDD'


def test_DHCP6OptIANAInstantiationwithalistofIAAddressesoptlenautomaticcomputation():
    """
    DHCP6OptIA_NA - Instantiation with a list of IA Addresses (optlen automatic computation) 
    """
    assert raw(DHCP6OptIA_NA(iaid=0x22222222, T1=0x33333333, T2=0x44444444,
                             ianaopts=[DHCP6OptIAAddress(),
                                       DHCP6OptIAAddress()])) == b'\x00\x03\x00D""""3333DDDD\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DHCP6OptIANADissectionwithspecificvalues():
    """
    DHCP6OptIA_NA - Dissection with specific values 
    """
    a = DHCP6OptIA_NA(
        b'\x00\x03\x00L""""3333DDDD\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.optcode == 3 and a.optlen == 76 and a.iaid == 0x22222222 and a.T1 == 0x33333333 and a.T2 == 0x44444444 and len(
        a.ianaopts) == 2 and isinstance(a.ianaopts[0],
                                        DHCP6OptIAAddress) and isinstance(
        a.ianaopts[1], DHCP6OptIAAddress)


def test_DHCP6OptIANAInstantiationwithalistofdifferentoptsIAAddressandStatusCodeoptlenautomaticcomputation():
    """
    DHCP6OptIA_NA - Instantiation with a list of different opts: IA Address and Status Code (optlen automatic computation) 
    """
    assert raw(DHCP6OptIA_NA(iaid=0x22222222, T1=0x33333333, T2=0x44444444,
                             ianaopts=[DHCP6OptIAAddress(),
                                       DHCP6OptStatusCode(statuscode=0xff,
                                                          statusmsg="Hello")])) == b'\x00\x03\x003""""3333DDDD\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\x00\x07\x00\xffHello'


def test_DHCP6OptIATABasicInstantiation():
    """
    DHCP6OptIA_TA - Basic Instantiation
    """
    assert raw(DHCP6OptIA_TA()) == b'\x00\x04\x00\x04\x00\x00\x00\x00'


def test_DHCP6OptIATABasicDissection():
    """
    DHCP6OptIA_TA - Basic Dissection 
    """
    a = DHCP6OptIA_TA(b'\x00\x04\x00\x04\x00\x00\x00\x00')
    assert a.optcode == 4 and a.optlen == 4 and a.iaid == 0 and a.iataopts == []


def test_DHCP6OptIATAInstantiationwithspecificvalues():
    """
    DHCP6OptIA_TA - Instantiation with specific values 
    """
    assert raw(DHCP6OptIA_TA(optlen=0x1111, iaid=0x22222222,
                             iataopts=[DHCP6OptIAAddress(),
                                       DHCP6OptIAAddress()])) == b'\x00\x04\x11\x11""""\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DHCP6OptIATADissectionwithspecificvalues():
    """
    DHCP6OptIA_TA - Dissection with specific values 
    """
    a = DHCP6OptIA_TA(
        b'\x00\x04\x11\x11""""\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    a.optcode == 4 and a.optlen == 0x1111 and a.iaid == 0x22222222 and len(
        a.iataopts) == 2 and isinstance(a.iataopts[0],
                                        DHCP6OptIAAddress) and isinstance(
        a.iataopts[1], DHCP6OptIAAddress)


def test_DHCP6OptIATAInstantiationwithalistofdifferentoptsIAAddressandStatusCodeoptlenautomaticcomputation():
    """
    DHCP6OptIA_TA - Instantiation with a list of different opts: IA Address and Status Code (optlen automatic computation) 
    """
    assert raw(DHCP6OptIA_TA(iaid=0x22222222, iataopts=[DHCP6OptIAAddress(),
                                                        DHCP6OptStatusCode(
                                                            statuscode=0xff,
                                                            statusmsg="Hello")])) == b'\x00\x04\x00+""""\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\x00\x07\x00\xffHello'


def test_DHCP6OptOptReqBasicInstantiation():
    """
    DHCP6OptOptReq - Basic Instantiation
    """
    assert raw(DHCP6OptOptReq()) == b'\x00\x06\x00\x04\x00\x17\x00\x18'


def test_DHCP6OptOptReqoptlenfieldcomputation():
    """
    DHCP6OptOptReq - optlen field computation 
    """
    assert raw(DHCP6OptOptReq(reqopts=[1, 2, 3,
                                       4])) == b'\x00\x06\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04'


def test_DHCP6OptOptReqinstantiationwithemptylist():
    """
    DHCP6OptOptReq - instantiation with empty list 
    """
    assert raw(DHCP6OptOptReq(reqopts=[])) == b'\x00\x06\x00\x00'


def test_DHCP6OptOptReqBasicdissection():
    """
    DHCP6OptOptReq - Basic dissection 
    """
    a = DHCP6OptOptReq(b'\x00\x06\x00\x00')
    assert a.optcode == 6 and a.optlen == 0 and a.reqopts == [23, 24]


def test_DHCP6OptOptReqDissectionwithspecificvalue():
    """
    DHCP6OptOptReq - Dissection with specific value 
    """
    a = DHCP6OptOptReq(b'\x00\x06\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04')
    assert a.optcode == 6 and a.optlen == 8 and a.reqopts == [1, 2, 3, 4]


def test_DHCP6OptOptReqrepr():
    """
    DHCP6OptOptReq - repr 
    """
    a = DHCP6OptOptReq(b'\x00\x06\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04')
    a.show()
    assert a is not None


def test_DHCP6OptPrefBasicinstantiation():
    """
    DHCP6OptPref - Basic instantiation
    """
    assert raw(DHCP6OptPref()) == b'\x00\x07\x00\x01\xff'


def test_DHCP6OptPrefInstantiationwithspecificvalues():
    """
    DHCP6OptPref - Instantiation with specific values 
    """
    assert raw(
        DHCP6OptPref(optlen=0xffff, prefval=0x11)) == b'\x00\x07\xff\xff\x11'


def test_DHCP6OptPrefBasicDissection():
    """
    DHCP6OptPref - Basic Dissection 
    """
    a = DHCP6OptPref(b'\x00\x07\x00\x01\xff')
    assert a.optcode == 7 and a.optlen == 1 and a.prefval == 255


def test_DHCP6OptPrefDissectionwithspecificvalues():
    """
    DHCP6OptPref - Dissection with specific values 
    """
    a = DHCP6OptPref(b'\x00\x07\xff\xff\x11')
    assert a.optcode == 7 and a.optlen == 0xffff and a.prefval == 0x11


def test_DHCP6OptElapsedTimeBasicInstantiation():
    """
    DHCP6OptElapsedTime - Basic Instantiation
    """
    assert raw(DHCP6OptElapsedTime()) == b'\x00\x08\x00\x02\x00\x00'


def test_DHCP6OptElapsedTimeInstantiationwithspecificelapsedtimevalue():
    """
    DHCP6OptElapsedTime - Instantiation with specific elapsedtime value 
    """
    assert raw(
        DHCP6OptElapsedTime(elapsedtime=421)) == b'\x00\x08\x00\x02\x01\xa5'


def test_DHCP6OptElapsedTimeBasicDissection():
    """
    DHCP6OptElapsedTime - Basic Dissection 
    """
    a = DHCP6OptElapsedTime(b'\x00\x08\x00\x02\x00\x00')
    assert a.optcode == 8 and a.optlen == 2 and a.elapsedtime == 0


def test_DHCP6OptElapsedTimeDissectionwithspecificvalues():
    """
    DHCP6OptElapsedTime - Dissection with specific values 
    """
    a = DHCP6OptElapsedTime(b'\x00\x08\x00\x02\x01\xa5')
    assert a.optcode == 8 and a.optlen == 2 and a.elapsedtime == 421


def test_DHCP6OptElapsedTimeRepr():
    """
    DHCP6OptElapsedTime - Repr 
    """
    a = DHCP6OptElapsedTime(b'\x00\x08\x00\x02\x01\xa5')
    a.show()
    assert a is not None


def test_DHCP6OptServerUnicastBasicInstantiation():
    """
    DHCP6OptServerUnicast - Basic Instantiation
    """
    assert raw(
        DHCP6OptServerUnicast()) == b'\x00\x0c\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DHCP6OptServerUnicastInstantiationwithspecificvaluestest1():
    """
    DHCP6OptServerUnicast - Instantiation with specific values (test 1) 
    """
    assert raw(DHCP6OptServerUnicast(
        srvaddr="2001::1")) == b'\x00\x0c\x00\x10 \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def test_DHCP6OptServerUnicastInstantiationwithspecificvaluestest2():
    """
    DHCP6OptServerUnicast - Instantiation with specific values (test 2) 
    """
    assert raw(DHCP6OptServerUnicast(srvaddr="2001::1",
                                     optlen=42)) == b'\x00\x0c\x00* \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def test_DHCP6OptServerUnicastDissectionwithdefaultvalues():
    """
    DHCP6OptServerUnicast - Dissection with default values 
    """
    a = DHCP6OptServerUnicast(
        b'\x00\x0c\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    a.optcode == 12 and a.optlen == 16 and a.srvaddr == "::"


def test_DHCP6OptServerUnicastDissectionwithspecificvaluestest1():
    """
    DHCP6OptServerUnicast - Dissection with specific values (test 1) 
    """
    a = DHCP6OptServerUnicast(
        b'\x00\x0c\x00\x10 \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 12 and a.optlen == 16 and a.srvaddr == "2001::1"


def test_DHCP6OptServerUnicastDissectionwithspecificvaluestest2():
    """
    DHCP6OptServerUnicast - Dissection with specific values (test 2) 
    """
    a = DHCP6OptServerUnicast(
        b'\x00\x0c\x00* \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 12 and a.optlen == 42 and a.srvaddr == "2001::1"


def test_DHCP6OptStatusCodeBasicInstantiation():
    """
    DHCP6OptStatusCode - Basic Instantiation
    """
    assert raw(DHCP6OptStatusCode()) == b'\x00\r\x00\x02\x00\x00'


def test_DHCP6OptStatusCodeInstantiationwithspecificvalues():
    """
    DHCP6OptStatusCode - Instantiation with specific values 
    """
    assert raw(DHCP6OptStatusCode(optlen=42, statuscode=0xff,
                                  statusmsg="Hello")) == b'\x00\r\x00*\x00\xffHello'


def test_DHCP6OptStatusCodeAutomaticLengthcomputation():
    """
    DHCP6OptStatusCode - Automatic Length computation 
    """
    assert raw(DHCP6OptStatusCode(statuscode=0xff,
                                  statusmsg="Hello")) == b'\x00\r\x00\x07\x00\xffHello'


def test_DHCP6OptRapidCommitBasicInstantiation():
    """
    DHCP6OptRapidCommit - Basic Instantiation
    """
    assert raw(DHCP6OptRapidCommit()) == b'\x00\x0e\x00\x00'


def test_DHCP6OptRapidCommitBasicDissection():
    """
    DHCP6OptRapidCommit - Basic Dissection 
    """
    a = DHCP6OptRapidCommit(b'\x00\x0e\x00\x00')
    assert a.optcode == 14 and a.optlen == 0


def test_DHCP6OptUserClassBasicInstantiation():
    """
    DHCP6OptUserClass - Basic Instantiation
    """
    assert raw(DHCP6OptUserClass()) == b'\x00\x0f\x00\x00'


def test_DHCP6OptUserClassBasicDissection():
    """
    DHCP6OptUserClass - Basic Dissection 
    """
    a = DHCP6OptUserClass(b'\x00\x0f\x00\x00')
    assert a.optcode == 15 and a.optlen == 0 and a.userclassdata == []


def test_DHCP6OptUserClassInstantiationwithoneuserclassdatarawucture():
    """
    DHCP6OptUserClass - Instantiation with one user class data rawucture 
    """
    assert raw(DHCP6OptUserClass(userclassdata=[USER_CLASS_DATA(
        data="something")])) == b'\x00\x0f\x00\x0b\x00\tsomething'


def test_DHCP6OptUserClassDissectionwithoneuserclassdatarawucture():
    """
    DHCP6OptUserClass - Dissection with one user class data rawucture 
    """
    a = DHCP6OptUserClass(b'\x00\x0f\x00\x0b\x00\tsomething')
    assert a.optcode == 15 and a.optlen == 11 and len(
        a.userclassdata) == 1 and isinstance(a.userclassdata[0],
                                             USER_CLASS_DATA) and \
           a.userclassdata[0].len == 9 and a.userclassdata[
               0].data == b'something'


def test_DHCP6OptUserClassInstantiationwithtwouserclassdatarawuctures():
    """
    DHCP6OptUserClass - Instantiation with two user class data rawuctures 
    """
    assert raw(DHCP6OptUserClass(
        userclassdata=[USER_CLASS_DATA(data="something"), USER_CLASS_DATA(
            data="somethingelse")])) == b'\x00\x0f\x00\x1a\x00\tsomething\x00\rsomethingelse'


def test_DHCP6OptUserClassDissectionwithtwouserclassdatarawuctures():
    """
    DHCP6OptUserClass - Dissection with two user class data rawuctures 
    """
    a = DHCP6OptUserClass(b'\x00\x0f\x00\x1a\x00\tsomething\x00\rsomethingelse')
    assert a.optcode == 15 and a.optlen == 26 and len(
        a.userclassdata) == 2 and isinstance(a.userclassdata[0],
                                             USER_CLASS_DATA) and isinstance(
        a.userclassdata[1], USER_CLASS_DATA) and a.userclassdata[0].len == 9 and \
           a.userclassdata[0].data == b'something' and a.userclassdata[
               1].len == 13 and a.userclassdata[1].data == b'somethingelse'


def test_DHCP6OptVendorClassBasicInstantiation():
    """
    DHCP6OptVendorClass - Basic Instantiation
    """
    assert raw(DHCP6OptVendorClass()) == b'\x00\x10\x00\x04\x00\x00\x00\x00'


def test_DHCP6OptVendorClassBasicDissection():
    """
    DHCP6OptVendorClass - Basic Dissection 
    """
    a = DHCP6OptVendorClass(b'\x00\x10\x00\x04\x00\x00\x00\x00')
    assert a.optcode == 16 and a.optlen == 4 and a.enterprisenum == 0 and a.vcdata == []


def test_DHCP6OptVendorClassInstantiationwithonevendorclassdatarawucture():
    """
    DHCP6OptVendorClass - Instantiation with one vendor class data rawucture 
    """
    assert raw(DHCP6OptVendorClass(vcdata=[VENDOR_CLASS_DATA(
        data="something")])) == b'\x00\x10\x00\x0f\x00\x00\x00\x00\x00\tsomething'


def test_DHCP6OptVendorClassDissectionwithonevendorclassdatarawucture():
    """
    DHCP6OptVendorClass - Dissection with one vendor class data rawucture 
    """
    a = DHCP6OptVendorClass(b'\x00\x10\x00\x0f\x00\x00\x00\x00\x00\tsomething')
    assert a.optcode == 16 and a.optlen == 15 and a.enterprisenum == 0 and len(
        a.vcdata) == 1 and isinstance(a.vcdata[0], VENDOR_CLASS_DATA) and \
           a.vcdata[0].len == 9 and a.vcdata[0].data == b'something'


def test_DHCP6OptVendorClassInstantiationwithtwovendorclassdatarawuctures():
    """
    DHCP6OptVendorClass - Instantiation with two vendor class data rawuctures 
    """
    assert raw(DHCP6OptVendorClass(vcdata=[VENDOR_CLASS_DATA(data="something"),
                                           VENDOR_CLASS_DATA(
                                               data="somethingelse")])) == b'\x00\x10\x00\x1e\x00\x00\x00\x00\x00\tsomething\x00\rsomethingelse'


def test_DHCP6OptVendorClassDissectionwithtwovendorclassdatarawuctures():
    """
    DHCP6OptVendorClass - Dissection with two vendor class data rawuctures 
    """
    a = DHCP6OptVendorClass(
        b'\x00\x10\x00\x1e\x00\x00\x00\x00\x00\tsomething\x00\rsomethingelse')
    assert a.optcode == 16 and a.optlen == 30 and a.enterprisenum == 0 and len(
        a.vcdata) == 2 and isinstance(a.vcdata[0],
                                      VENDOR_CLASS_DATA) and isinstance(
        a.vcdata[1], VENDOR_CLASS_DATA) and a.vcdata[0].len == 9 and a.vcdata[
               0].data == b'something' and a.vcdata[1].len == 13 and a.vcdata[
               1].data == b'somethingelse'


def test_DHCP6OptVendorSpecificInfoBasicInstantiation():
    """
    DHCP6OptVendorSpecificInfo - Basic Instantiation
    """
    assert raw(
        DHCP6OptVendorSpecificInfo()) == b'\x00\x11\x00\x04\x00\x00\x00\x00'


def test_DHCP6OptVendorSpecificInfoBasicDissection():
    """
    DHCP6OptVendorSpecificInfo - Basic Dissection 
    """
    a = DHCP6OptVendorSpecificInfo(b'\x00\x11\x00\x04\x00\x00\x00\x00')
    assert a.optcode == 17 and a.optlen == 4 and a.enterprisenum == 0


def test_DHCP6OptVendorSpecificInfoInstantiationwithspecificvaluesoneoption():
    """
    DHCP6OptVendorSpecificInfo - Instantiation with specific values (one option) 
    """
    assert raw(DHCP6OptVendorSpecificInfo(enterprisenum=0xeeeeeeee, vso=[
        VENDOR_SPECIFIC_OPTION(optcode=43,
                               optdata="something")])) == b'\x00\x11\x00\x11\xee\xee\xee\xee\x00+\x00\tsomething'


def test_DHCP6OptVendorSpecificInfoDissectionwithwithspecificvaluesoneoption():
    """
    DHCP6OptVendorSpecificInfo - Dissection with with specific values (one option) 
    """
    a = DHCP6OptVendorSpecificInfo(
        b'\x00\x11\x00\x11\xee\xee\xee\xee\x00+\x00\tsomething')
    assert a.optcode == 17 and a.optlen == 17 and a.enterprisenum == 0xeeeeeeee and len(
        a.vso) == 1 and isinstance(a.vso[0], VENDOR_SPECIFIC_OPTION) and a.vso[
               0].optlen == 9 and a.vso[0].optdata == b'something'


def test_DHCP6OptVendorSpecificInfoInstantiationwithspecificvaluestwooptions():
    """
    DHCP6OptVendorSpecificInfo - Instantiation with specific values (two options) 
    """
    assert raw(DHCP6OptVendorSpecificInfo(enterprisenum=0xeeeeeeee, vso=[
        VENDOR_SPECIFIC_OPTION(optcode=43, optdata="something"),
        VENDOR_SPECIFIC_OPTION(optcode=42,
                               optdata="somethingelse")])) == b'\x00\x11\x00"\xee\xee\xee\xee\x00+\x00\tsomething\x00*\x00\rsomethingelse'


def test_DHCP6OptVendorSpecificInfoDissectionwithwithspecificvaluestwooptions():
    """
    DHCP6OptVendorSpecificInfo - Dissection with with specific values (two options) 
    """
    a = DHCP6OptVendorSpecificInfo(
        b'\x00\x11\x00"\xee\xee\xee\xee\x00+\x00\tsomething\x00*\x00\rsomethingelse')
    assert a.optcode == 17 and a.optlen == 34 and a.enterprisenum == 0xeeeeeeee and len(
        a.vso) == 2 and isinstance(a.vso[0],
                                   VENDOR_SPECIFIC_OPTION) and isinstance(
        a.vso[1], VENDOR_SPECIFIC_OPTION) and a.vso[0].optlen == 9 and a.vso[
               0].optdata == b'something' and a.vso[1].optlen == 13 and a.vso[
               1].optdata == b'somethingelse'


def test_DHCP6OptIfaceIdBasicInstantiation():
    """
    DHCP6OptIfaceId - Basic Instantiation
    """
    assert raw(DHCP6OptIfaceId()) == b'\x00\x12\x00\x00'


def test_DHCP6OptIfaceIdBasicDissection():
    """
    DHCP6OptIfaceId - Basic Dissection 
    """
    a = DHCP6OptIfaceId(b'\x00\x12\x00\x00')
    assert a.optcode == 18 and a.optlen == 0


def test_DHCP6OptIfaceIdInstantiationwithspecificvalue():
    """
    DHCP6OptIfaceId - Instantiation with specific value 
    """
    assert raw(
        DHCP6OptIfaceId(ifaceid="something")) == b'\x00\x12\x00\x09something'


def test_DHCP6OptIfaceIdDissectionwithspecificvalue():
    """
    DHCP6OptIfaceId - Dissection with specific value 
    """
    a = DHCP6OptIfaceId(b'\x00\x12\x00\x09something')
    assert a.optcode == 18 and a.optlen == 9 and a.ifaceid == b"something"


def test_DHCP6OptReconfMsgBasicInstantiation():
    """
    DHCP6OptReconfMsg - Basic Instantiation
    """
    assert raw(DHCP6OptReconfMsg()) == b'\x00\x13\x00\x01\x0b'


def test_DHCP6OptReconfMsgBasicDissection():
    """
    DHCP6OptReconfMsg - Basic Dissection 
    """
    a = DHCP6OptReconfMsg(b'\x00\x13\x00\x01\x0b')
    assert a.optcode == 19 and a.optlen == 1 and a.msgtype == 11


def test_DHCP6OptReconfMsgInstantiationwithspecificvalues():
    """
    DHCP6OptReconfMsg - Instantiation with specific values 
    """
    assert raw(
        DHCP6OptReconfMsg(optlen=4, msgtype=5)) == b'\x00\x13\x00\x04\x05'


def test_DHCP6OptReconfMsgDissectionwithspecificvalues():
    """
    DHCP6OptReconfMsg - Dissection with specific values 
    """
    a = DHCP6OptReconfMsg(b'\x00\x13\x00\x04\x05')
    assert a.optcode == 19 and a.optlen == 4 and a.msgtype == 5


def test_DHCP6OptReconfAcceptBasicInstantiation():
    """
    DHCP6OptReconfAccept - Basic Instantiation
    """
    assert raw(DHCP6OptReconfAccept()) == b'\x00\x14\x00\x00'


def test_DHCP6OptReconfAcceptBasicDissection():
    """
    DHCP6OptReconfAccept - Basic Dissection 
    """
    a = DHCP6OptReconfAccept(b'\x00\x14\x00\x00')
    assert a.optcode == 20 and a.optlen == 0


def test_DHCP6OptReconfAcceptInstantiationwithspecificvalues():
    """
    DHCP6OptReconfAccept - Instantiation with specific values 
    """
    assert raw(DHCP6OptReconfAccept(optlen=23)) == b'\x00\x14\x00\x17'


def test_DHCP6OptReconfAcceptDssectionwithspecificvalues():
    """
    DHCP6OptReconfAccept - Dssection with specific values 
    """
    a = DHCP6OptReconfAccept(b'\x00\x14\x00\x17')
    assert a.optcode == 20 and a.optlen == 23


def test_DHCP6OptSIPDomainsBasicInstantiation():
    """
    DHCP6OptSIPDomains - Basic Instantiation
    """
    assert raw(DHCP6OptSIPDomains()) == b'\x00\x15\x00\x00'


def test_DHCP6OptSIPDomainsBasicDissection():
    """
    DHCP6OptSIPDomains - Basic Dissection 
    """
    a = DHCP6OptSIPDomains(b'\x00\x15\x00\x00')
    assert a.optcode == 21 and a.optlen == 0 and a.sipdomains == []


def test_DHCP6OptSIPDomainsInstantiationwithonedomain():
    """
    DHCP6OptSIPDomains - Instantiation with one domain 
    """
    assert raw(DHCP6OptSIPDomains(sipdomains=[
        "toto.example.org"])) == b'\x00\x15\x00\x12\x04toto\x07example\x03org\x00'


def test_DHCP6OptSIPDomainsDissectionwithonedomain():
    """
    DHCP6OptSIPDomains - Dissection with one domain 
    """
    a = DHCP6OptSIPDomains(b'\x00\x15\x00\x12\x04toto\x07example\x03org\x00')
    assert a.optcode == 21 and a.optlen == 18 and len(a.sipdomains) == 1 and \
           a.sipdomains[0] == "toto.example.org."


def test_DHCP6OptSIPDomainsInstantiationwithtwodomains():
    """
    DHCP6OptSIPDomains - Instantiation with two domains 
    """
    assert raw(DHCP6OptSIPDomains(sipdomains=["toto.example.org",
                                              "titi.example.org"])) == b'\x00\x15\x00$\x04toto\x07example\x03org\x00\x04titi\x07example\x03org\x00'


def test_DHCP6OptSIPDomainsDissectionwithtwodomains():
    """
    DHCP6OptSIPDomains - Dissection with two domains 
    """
    a = DHCP6OptSIPDomains(
        b'\x00\x15\x00$\x04toto\x07example\x03org\x00\x04TITI\x07example\x03org\x00')
    assert a.optcode == 21 and a.optlen == 36 and len(a.sipdomains) == 2 and \
           a.sipdomains[0] == "toto.example.org." and a.sipdomains[
               1] == "TITI.example.org."


def test_DHCP6OptSIPDomainsEnforcingonlyonedotatendofdomain():
    """
    DHCP6OptSIPDomains - Enforcing only one dot at end of domain 
    """
    assert raw(DHCP6OptSIPDomains(sipdomains=[
        "toto.example.org."])) == b'\x00\x15\x00\x12\x04toto\x07example\x03org\x00'


def test_DHCP6OptSIPServersBasicInstantiation():
    """
    DHCP6OptSIPServers - Basic Instantiation
    """
    assert raw(DHCP6OptSIPServers()) == b'\x00\x16\x00\x00'


def test_DHCP6OptSIPServersBasicDissection():
    """
    DHCP6OptSIPServers - Basic Dissection 
    """
    a = DHCP6OptSIPServers(b'\x00\x16\x00\x00')
    assert a.optcode == 22 and a.optlen == 0 and a.sipservers == []


def test_DHCP6OptSIPServersInstantiationwithspecificvalues1address():
    """
    DHCP6OptSIPServers - Instantiation with specific values (1 address) 
    """
    assert raw(DHCP6OptSIPServers(sipservers=[
        "2001:db8::1"])) == b'\x00\x16\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def test_DHCP6OptSIPServersDissectionwithspecificvalues1address():
    """
    DHCP6OptSIPServers - Dissection with specific values (1 address) 
    """
    a = DHCP6OptSIPServers(
        b'\x00\x16\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 22 and a.optlen == 16 and len(a.sipservers) == 1 and \
           a.sipservers[0] == "2001:db8::1"


def test_DHCP6OptSIPServersInstantiationwithspecificvalues2addresses():
    """
    DHCP6OptSIPServers - Instantiation with specific values (2 addresses) 
    """
    assert raw(DHCP6OptSIPServers(sipservers=["2001:db8::1",
                                              "2001:db8::2"])) == b'\x00\x16\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


def test_DHCP6OptSIPServersDissectionwithspecificvalues2addresses():
    """
    DHCP6OptSIPServers - Dissection with specific values (2 addresses) 
    """
    a = DHCP6OptSIPServers(
        b'\x00\x16\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 22 and a.optlen == 32 and len(a.sipservers) == 2 and \
           a.sipservers[0] == "2001:db8::1" and a.sipservers[1] == "2001:db8::2"


def test_DHCP6OptDNSServersBasicInstantiation():
    """
    DHCP6OptDNSServers - Basic Instantiation
    """
    assert raw(DHCP6OptDNSServers()) == b'\x00\x17\x00\x00'


def test_DHCP6OptDNSServersBasicDissection():
    """
    DHCP6OptDNSServers - Basic Dissection 
    """
    a = DHCP6OptDNSServers(b'\x00\x17\x00\x00')
    assert a.optcode == 23 and a.optlen == 0 and a.dnsservers == []


def test_DHCP6OptDNSServersInstantiationwithspecificvalues1address():
    """
    DHCP6OptDNSServers - Instantiation with specific values (1 address) 
    """
    assert raw(DHCP6OptDNSServers(dnsservers=[
        "2001:db8::1"])) == b'\x00\x17\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def test_DHCP6OptDNSServersDissectionwithspecificvalues1address():
    """
    DHCP6OptDNSServers - Dissection with specific values (1 address) 
    """
    a = DHCP6OptDNSServers(
        b'\x00\x17\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 23 and a.optlen == 16 and len(a.dnsservers) == 1 and \
           a.dnsservers[0] == "2001:db8::1"


def test_DHCP6OptDNSServersInstantiationwithspecificvalues2addresses():
    """
    DHCP6OptDNSServers - Instantiation with specific values (2 addresses) 
    """
    assert raw(DHCP6OptDNSServers(dnsservers=["2001:db8::1",
                                              "2001:db8::2"])) == b'\x00\x17\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


def test_DHCP6OptDNSServersDissectionwithspecificvalues2addresses():
    """
    DHCP6OptDNSServers - Dissection with specific values (2 addresses) 
    """
    a = DHCP6OptDNSServers(
        b'\x00\x17\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 23 and a.optlen == 32 and len(a.dnsservers) == 2 and \
           a.dnsservers[0] == "2001:db8::1" and a.dnsservers[1] == "2001:db8::2"


def test_DHCP6OptDNSDomainsBasicInstantiation():
    """
    DHCP6OptDNSDomains - Basic Instantiation
    """
    assert raw(DHCP6OptDNSDomains()) == b'\x00\x18\x00\x00'


def test_DHCP6OptDNSDomainsBasicDissection():
    """
    DHCP6OptDNSDomains - Basic Dissection 
    """
    a = DHCP6OptDNSDomains(b'\x00\x18\x00\x00')
    assert a.optcode == 24 and a.optlen == 0 and a.dnsdomains == []


def test_DHCP6OptDNSDomainsInstantiationwithspecificvalues1domain():
    """
    DHCP6OptDNSDomains - Instantiation with specific values (1 domain) 
    """
    assert raw(DHCP6OptDNSDomains(dnsdomains=[
        "toto.example.com."])) == b'\x00\x18\x00\x12\x04toto\x07example\x03com\x00'


def test_DHCP6OptDNSDomainsDissectionwithspecificvalues1domain():
    """
    DHCP6OptDNSDomains - Dissection with specific values (1 domain) 
    """
    a = DHCP6OptDNSDomains(b'\x00\x18\x00\x12\x04toto\x07example\x03com\x00')
    assert a.optcode == 24 and a.optlen == 18 and len(a.dnsdomains) == 1 and \
           a.dnsdomains[0] == "toto.example.com."


def test_DHCP6OptDNSDomainsInstantiationwithspecificvalues2domains():
    """
    DHCP6OptDNSDomains - Instantiation with specific values (2 domains) 
    """
    assert raw(DHCP6OptDNSDomains(dnsdomains=["toto.example.com.",
                                              "titi.example.com."])) == b'\x00\x18\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00'


def test_DHCP6OptDNSDomainsDissectionwithspecificvalues2domains():
    """
    DHCP6OptDNSDomains - Dissection with specific values (2 domains) 
    """
    a = DHCP6OptDNSDomains(
        b'\x00\x18\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00')
    assert a.optcode == 24 and a.optlen == 36 and len(a.dnsdomains) == 2 and \
           a.dnsdomains[0] == "toto.example.com." and a.dnsdomains[
               1] == "titi.example.com."


def test_DHCP6OptIAPrefixBasicInstantiation():
    """
    DHCP6OptIAPrefix - Basic Instantiation
    """
    assert raw(
        DHCP6OptIAPrefix()) == b'\x00\x1a\x00\x19\x00\x00\x00\x00\x00\x00\x00\x000 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DHCP6OptIAPDBasicInstantiation():
    """
    DHCP6OptIA_PD - Basic Instantiation
    """
    assert raw(
        DHCP6OptIA_PD()) == b'\x00\x19\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DHCP6OptIAPDInstantiationwithalistofdifferentoptsIAAddressandStatusCodeoptlenautomaticcomputation():
    """
    DHCP6OptIA_PD - Instantiation with a list of different opts: IA Address and Status Code (optlen automatic computation) 
    """
    assert raw(DHCP6OptIA_PD(iaid=0x22222222, T1=0x33333333, T2=0x44444444,
                             iapdopt=[DHCP6OptIAAddress(),
                                      DHCP6OptStatusCode(statuscode=0xff,
                                                         statusmsg="Hello")])) == b'\x00\x19\x003""""3333DDDD\x00\x05\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\x00\x07\x00\xffHello'


def test_DHCP6OptNISServersBasicInstantiation():
    """
    DHCP6OptNISServers - Basic Instantiation
    """
    assert raw(DHCP6OptNISServers()) == b'\x00\x1b\x00\x00'


def test_DHCP6OptNISServersBasicDissection():
    """
    DHCP6OptNISServers - Basic Dissection 
    """
    a = DHCP6OptNISServers(b'\x00\x1b\x00\x00')
    assert a.optcode == 27 and a.optlen == 0 and a.nisservers == []


def test_DHCP6OptNISServersInstantiationwithspecificvalues1address():
    """
    DHCP6OptNISServers - Instantiation with specific values (1 address) 
    """
    assert raw(DHCP6OptNISServers(nisservers=[
        "2001:db8::1"])) == b'\x00\x1b\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def test_DHCP6OptNISServersDissectionwithspecificvalues1address():
    """
    DHCP6OptNISServers - Dissection with specific values (1 address) 
    """
    a = DHCP6OptNISServers(
        b'\x00\x1b\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 27 and a.optlen == 16 and len(a.nisservers) == 1 and \
           a.nisservers[0] == "2001:db8::1"


def test_DHCP6OptNISServersInstantiationwithspecificvalues2addresses():
    """
    DHCP6OptNISServers - Instantiation with specific values (2 addresses) 
    """
    assert raw(DHCP6OptNISServers(nisservers=["2001:db8::1",
                                              "2001:db8::2"])) == b'\x00\x1b\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


def test_DHCP6OptNISServersDissectionwithspecificvalues2addresses():
    """
    DHCP6OptNISServers - Dissection with specific values (2 addresses) 
    """
    a = DHCP6OptNISServers(
        b'\x00\x1b\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 27 and a.optlen == 32 and len(a.nisservers) == 2 and \
           a.nisservers[0] == "2001:db8::1" and a.nisservers[1] == "2001:db8::2"


def test_DHCP6OptNISPServersBasicInstantiation():
    """
    DHCP6OptNISPServers - Basic Instantiation
    """
    assert raw(DHCP6OptNISPServers()) == b'\x00\x1c\x00\x00'


def test_DHCP6OptNISPServersBasicDissection():
    """
    DHCP6OptNISPServers - Basic Dissection 
    """
    a = DHCP6OptNISPServers(b'\x00\x1c\x00\x00')
    assert a.optcode == 28 and a.optlen == 0 and a.nispservers == []


def test_DHCP6OptNISPServersInstantiationwithspecificvalues1address():
    """
    DHCP6OptNISPServers - Instantiation with specific values (1 address) 
    """
    assert raw(DHCP6OptNISPServers(nispservers=[
        "2001:db8::1"])) == b'\x00\x1c\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def test_DHCP6OptNISPServersDissectionwithspecificvalues1address():
    """
    DHCP6OptNISPServers - Dissection with specific values (1 address) 
    """
    a = DHCP6OptNISPServers(
        b'\x00\x1c\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 28 and a.optlen == 16 and len(a.nispservers) == 1 and \
           a.nispservers[0] == "2001:db8::1"


def test_DHCP6OptNISPServersInstantiationwithspecificvalues2addresses():
    """
    DHCP6OptNISPServers - Instantiation with specific values (2 addresses) 
    """
    assert raw(DHCP6OptNISPServers(nispservers=["2001:db8::1",
                                                "2001:db8::2"])) == b'\x00\x1c\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


def test_DHCP6OptNISPServersDissectionwithspecificvalues2addresses():
    """
    DHCP6OptNISPServers - Dissection with specific values (2 addresses) 
    """
    a = DHCP6OptNISPServers(
        b'\x00\x1c\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 28 and a.optlen == 32 and len(a.nispservers) == 2 and \
           a.nispservers[0] == "2001:db8::1" and a.nispservers[
               1] == "2001:db8::2"


def test_DHCP6OptNISDomainBasicInstantiation():
    """
    DHCP6OptNISDomain - Basic Instantiation
    """
    assert raw(DHCP6OptNISDomain()) == b'\x00\x1d\x00\x01\x00'


def test_DHCP6OptNISDomainBasicDissection():
    """
    DHCP6OptNISDomain - Basic Dissection 
    """
    a = DHCP6OptNISDomain(b'\x00\x1d\x00\x00')
    assert a.optcode == 29 and a.optlen == 0 and a.nisdomain == b"."


def test_DHCP6OptNISDomainInstantiationwithonedomainname():
    """
    DHCP6OptNISDomain - Instantiation with one domain name 
    """
    assert raw(DHCP6OptNISDomain(
        nisdomain="toto.example.org")) == b'\x00\x1d\x00\x12\x04toto\x07example\x03org\x00'


def test_DHCP6OptNISDomainDissectionwithonedomainname():
    """
    DHCP6OptNISDomain - Dissection with one domain name 
    """
    a = DHCP6OptNISDomain(b'\x00\x1d\x00\x11\x04toto\x07example\x03org\x00')
    assert a.optcode == 29 and a.optlen == 17 and a.nisdomain == b"toto.example.org."


def test_DHCP6OptNISDomainInstantiationwithonedomainwithtrailingdot():
    """
    DHCP6OptNISDomain - Instantiation with one domain with trailing dot 
    """
    assert raw(DHCP6OptNISDomain(
        nisdomain="toto.example.org.")) == b'\x00\x1d\x00\x12\x04toto\x07example\x03org\x00'


def test_DHCP6OptNISPDomainBasicInstantiation():
    """
    DHCP6OptNISPDomain - Basic Instantiation
    """
    assert raw(DHCP6OptNISPDomain()) == b'\x00\x1e\x00\x01\x00'


def test_DHCP6OptNISPDomainBasicDissection():
    """
    DHCP6OptNISPDomain - Basic Dissection 
    """
    a = DHCP6OptNISPDomain(b'\x00\x1e\x00\x00')
    assert a.optcode == 30 and a.optlen == 0 and a.nispdomain == b"."


def test_DHCP6OptNISPDomainInstantiationwithonedomainname():
    """
    DHCP6OptNISPDomain - Instantiation with one domain name 
    """
    assert raw(DHCP6OptNISPDomain(
        nispdomain="toto.example.org")) == b'\x00\x1e\x00\x12\x04toto\x07example\x03org\x00'


def test_DHCP6OptNISPDomainDissectionwithonedomainname():
    """
    DHCP6OptNISPDomain - Dissection with one domain name 
    """
    a = DHCP6OptNISPDomain(b'\x00\x1e\x00\x12\x04toto\x07example\x03org\x00')
    assert a.optcode == 30 and a.optlen == 18 and a.nispdomain == b"toto.example.org."


def test_DHCP6OptNISPDomainInstantiationwithonedomainwithtrailingdot():
    """
    DHCP6OptNISPDomain - Instantiation with one domain with trailing dot 
    """
    assert raw(DHCP6OptNISPDomain(
        nispdomain="toto.example.org.")) == b'\x00\x1e\x00\x12\x04toto\x07example\x03org\x00'


def test_DHCP6OptSNTPServersBasicInstantiation():
    """
    DHCP6OptSNTPServers - Basic Instantiation
    """
    assert raw(DHCP6OptSNTPServers()) == b'\x00\x1f\x00\x00'


def test_DHCP6OptSNTPServersBasicDissection():
    """
    DHCP6OptSNTPServers - Basic Dissection 
    """
    a = DHCP6OptSNTPServers(b'\x00\x1f\x00\x00')
    assert a.optcode == 31 and a.optlen == 0 and a.sntpservers == []


def test_DHCP6OptSNTPServersInstantiationwithspecificvalues1address():
    """
    DHCP6OptSNTPServers - Instantiation with specific values (1 address) 
    """
    assert raw(DHCP6OptSNTPServers(sntpservers=[
        "2001:db8::1"])) == b'\x00\x1f\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def test_DHCP6OptSNTPServersDissectionwithspecificvalues1address():
    """
    DHCP6OptSNTPServers - Dissection with specific values (1 address) 
    """
    a = DHCP6OptSNTPServers(
        b'\x00\x1f\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 31 and a.optlen == 16 and len(a.sntpservers) == 1 and \
           a.sntpservers[0] == "2001:db8::1"


def test_DHCP6OptSNTPServersInstantiationwithspecificvalues2addresses():
    """
    DHCP6OptSNTPServers - Instantiation with specific values (2 addresses) 
    """
    assert raw(DHCP6OptSNTPServers(sntpservers=["2001:db8::1",
                                                "2001:db8::2"])) == b'\x00\x1f\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


def test_DHCP6OptSNTPServersDissectionwithspecificvalues2addresses():
    """
    DHCP6OptSNTPServers - Dissection with specific values (2 addresses) 
    """
    a = DHCP6OptSNTPServers(
        b'\x00\x1f\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 31 and a.optlen == 32 and len(a.sntpservers) == 2 and \
           a.sntpservers[0] == "2001:db8::1" and a.sntpservers[
               1] == "2001:db8::2"


def test_DHCP6OptInfoRefreshTimeBasicInstantiation():
    """
    DHCP6OptInfoRefreshTime - Basic Instantiation
    """
    assert raw(DHCP6OptInfoRefreshTime()) == b'\x00 \x00\x04\x00\x01Q\x80'


def test_DHCP6OptInfoRefreshTimeBasicDissction():
    """
    DHCP6OptInfoRefreshTime - Basic Dissction 
    """
    a = DHCP6OptInfoRefreshTime(b'\x00 \x00\x04\x00\x01Q\x80')
    assert a.optcode == 32 and a.optlen == 4 and a.reftime == 86400


def test_DHCP6OptInfoRefreshTimeInstantiationwithspecificvalues():
    """
    DHCP6OptInfoRefreshTime - Instantiation with specific values 
    """
    assert raw(DHCP6OptInfoRefreshTime(optlen=7,
                                       reftime=42)) == b'\x00 \x00\x07\x00\x00\x00*'


def test_DHCP6OptBCMCSServersBasicInstantiation():
    """
    DHCP6OptBCMCSServers - Basic Instantiation
    """
    assert raw(DHCP6OptBCMCSServers()) == b'\x00"\x00\x00'


def test_DHCP6OptBCMCSServersBasicDissection():
    """
    DHCP6OptBCMCSServers - Basic Dissection 
    """
    a = DHCP6OptBCMCSServers(b'\x00"\x00\x00')
    assert a.optcode == 34 and a.optlen == 0 and a.bcmcsservers == []


def test_DHCP6OptBCMCSServersInstantiationwithspecificvalues1address():
    """
    DHCP6OptBCMCSServers - Instantiation with specific values (1 address) 
    """
    assert raw(DHCP6OptBCMCSServers(bcmcsservers=[
        "2001:db8::1"])) == b'\x00"\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def test_DHCP6OptBCMCSServersDissectionwithspecificvalues1address():
    """
    DHCP6OptBCMCSServers - Dissection with specific values (1 address) 
    """
    a = DHCP6OptBCMCSServers(
        b'\x00"\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 34 and a.optlen == 16 and len(a.bcmcsservers) == 1 and \
           a.bcmcsservers[0] == "2001:db8::1"


def test_DHCP6OptBCMCSServersInstantiationwithspecificvalues2addresses():
    """
    DHCP6OptBCMCSServers - Instantiation with specific values (2 addresses) 
    """
    assert raw(DHCP6OptBCMCSServers(bcmcsservers=["2001:db8::1",
                                                  "2001:db8::2"])) == b'\x00"\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


def test_DHCP6OptBCMCSServersDissectionwithspecificvalues2addresses():
    """
    DHCP6OptBCMCSServers - Dissection with specific values (2 addresses) 
    """
    a = DHCP6OptBCMCSServers(
        b'\x00"\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 34 and a.optlen == 32 and len(a.bcmcsservers) == 2 and \
           a.bcmcsservers[0] == "2001:db8::1" and a.bcmcsservers[
               1] == "2001:db8::2"


def test_DHCP6OptBCMCSDomainsBasicInstantiation():
    """
    DHCP6OptBCMCSDomains - Basic Instantiation
    """
    assert raw(DHCP6OptBCMCSDomains()) == b'\x00!\x00\x00'


def test_DHCP6OptBCMCSDomainsBasicDissection():
    """
    DHCP6OptBCMCSDomains - Basic Dissection 
    """
    a = DHCP6OptBCMCSDomains(b'\x00!\x00\x00')
    assert a.optcode == 33 and a.optlen == 0 and a.bcmcsdomains == []


def test_DHCP6OptBCMCSDomainsInstantiationwithspecificvalues1domain():
    """
    DHCP6OptBCMCSDomains - Instantiation with specific values (1 domain) 
    """
    assert raw(DHCP6OptBCMCSDomains(bcmcsdomains=[
        "toto.example.com."])) == b'\x00!\x00\x12\x04toto\x07example\x03com\x00'


def test_DHCP6OptBCMCSDomainsDissectionwithspecificvalues1domain():
    """
    DHCP6OptBCMCSDomains - Dissection with specific values (1 domain) 
    """
    a = DHCP6OptBCMCSDomains(b'\x00!\x00\x12\x04toto\x07example\x03com\x00')
    assert a.optcode == 33 and a.optlen == 18 and len(a.bcmcsdomains) == 1 and \
           a.bcmcsdomains[0] == "toto.example.com."


def test_DHCP6OptBCMCSDomainsInstantiationwithspecificvalues2domains():
    """
    DHCP6OptBCMCSDomains - Instantiation with specific values (2 domains) 
    """
    assert raw(DHCP6OptBCMCSDomains(bcmcsdomains=["toto.example.com.",
                                                  "titi.example.com."])) == b'\x00!\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00'


def test_DHCP6OptBCMCSDomainsDissectionwithspecificvalues2domains():
    """
    DHCP6OptBCMCSDomains - Dissection with specific values (2 domains) 
    """
    a = DHCP6OptBCMCSDomains(
        b'\x00!\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00')
    assert a.optcode == 33 and a.optlen == 36 and len(a.bcmcsdomains) == 2 and \
           a.bcmcsdomains[0] == "toto.example.com." and a.bcmcsdomains[
               1] == "titi.example.com."


def test_DHCP6OptRemoteIDBasicInstantiation():
    """
    DHCP6OptRemoteID - Basic Instantiation
    """
    assert raw(DHCP6OptRemoteID()) == b'\x00%\x00\x04\x00\x00\x00\x00'


def test_DHCP6OptRemoteIDBasicDissection():
    """
    DHCP6OptRemoteID - Basic Dissection 
    """
    a = DHCP6OptRemoteID(b'\x00%\x00\x04\x00\x00\x00\x00')
    assert a.optcode == 37 and a.optlen == 4 and a.enterprisenum == 0 and a.remoteid == b""


def test_DHCP6OptRemoteIDInstantiationwithspecificvalues():
    """
    DHCP6OptRemoteID - Instantiation with specific values 
    """
    assert raw(DHCP6OptRemoteID(enterprisenum=0xeeeeeeee,
                                remoteid="someid")) == b'\x00%\x00\n\xee\xee\xee\xeesomeid'


def test_DHCP6OptRemoteIDDissectionwithspecificvalues():
    """
    DHCP6OptRemoteID - Dissection with specific values 
    """
    a = DHCP6OptRemoteID(b'\x00%\x00\n\xee\xee\xee\xeesomeid')
    assert a.optcode == 37 and a.optlen == 10 and a.enterprisenum == 0xeeeeeeee and a.remoteid == b"someid"


def test_DHCP6OptSubscriberIDBasicInstantiation():
    """
    DHCP6OptSubscriberID - Basic Instantiation
    """
    assert raw(DHCP6OptSubscriberID()) == b'\x00&\x00\x00'


def test_DHCP6OptSubscriberIDBasicDissection():
    """
    DHCP6OptSubscriberID - Basic Dissection 
    """
    a = DHCP6OptSubscriberID(b'\x00&\x00\x00')
    assert a.optcode == 38 and a.optlen == 0 and a.subscriberid == b""


def test_DHCP6OptSubscriberIDInstantiationwithspecificvalues():
    """
    DHCP6OptSubscriberID - Instantiation with specific values 
    """
    assert raw(
        DHCP6OptSubscriberID(subscriberid="someid")) == b'\x00&\x00\x06someid'


def test_DHCP6OptSubscriberIDDissectionwithspecificvalues():
    """
    DHCP6OptSubscriberID - Dissection with specific values 
    """
    a = DHCP6OptSubscriberID(b'\x00&\x00\x06someid')
    assert a.optcode == 38 and a.optlen == 6 and a.subscriberid == b"someid"


def test_DHCP6OptClientFQDNBasicInstantiation():
    """
    DHCP6OptClientFQDN - Basic Instantiation
    """
    assert raw(DHCP6OptClientFQDN()) == b"\x00'\x00\x02\x00\x00"


def test_DHCP6OptClientFQDNBasicDissection():
    """
    DHCP6OptClientFQDN - Basic Dissection 
    """
    a = DHCP6OptClientFQDN(b"\x00'\x00\x01\x00")
    assert a.optcode == 39 and a.optlen == 1 and a.res == 0 and a.flags == 0 and a.fqdn == b"."


def test_DHCP6OptClientFQDNInstantiationwithvariousflagscombinations():
    """
    DHCP6OptClientFQDN - Instantiation with various flags combinations 
    """
    assert raw(
        DHCP6OptClientFQDN(flags="S")) == b"\x00'\x00\x02\x01\x00" and raw(
        DHCP6OptClientFQDN(flags="O")) == b"\x00'\x00\x02\x02\x00" and raw(
        DHCP6OptClientFQDN(flags="N")) == b"\x00'\x00\x02\x04\x00" and raw(
        DHCP6OptClientFQDN(flags="SON")) == b"\x00'\x00\x02\x07\x00" and raw(
        DHCP6OptClientFQDN(flags="ON")) == b"\x00'\x00\x02\x06\x00"


def test_DHCP6OptClientFQDNInstantiationwithonefqdn():
    """
    DHCP6OptClientFQDN - Instantiation with one fqdn 
    """
    assert raw(DHCP6OptClientFQDN(
        fqdn="toto.example.org")) == b"\x00'\x00\x13\x00\x04toto\x07example\x03org\x00"


def test_DHCP6OptClientFQDNDissectionwithonefqdn():
    """
    DHCP6OptClientFQDN - Dissection with one fqdn 
    """
    a = DHCP6OptClientFQDN(b"\x00'\x00\x12\x00\x04toto\x07example\x03org\x00")
    assert a.optcode == 39 and a.optlen == 18 and a.res == 0 and a.flags == 0 and a.fqdn == b"toto.example.org."


def test_DHCP6OptPanaAuthAgentBasicInstantiation():
    """
    DHCP6OptPanaAuthAgent - Basic Instantiation
    """
    assert raw(DHCP6OptPanaAuthAgent()) == b'\x00(\x00\x00'


def test_DHCP6OptPanaAuthAgentBasicDissection():
    """
    DHCP6OptPanaAuthAgent - Basic Dissection 
    """
    a = DHCP6OptPanaAuthAgent(b"\x00(\x00\x00")
    assert a.optcode == 40 and a.optlen == 0 and a.paaaddr == []


def test_DHCP6OptPanaAuthAgentInstantiationwithspecificvalues1address():
    """
    DHCP6OptPanaAuthAgent - Instantiation with specific values (1 address) 
    """
    assert raw(DHCP6OptPanaAuthAgent(paaaddr=[
        "2001:db8::1"])) == b'\x00(\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def test_DHCP6OptPanaAuthAgentDissectionwithspecificvalues1address():
    """
    DHCP6OptPanaAuthAgent - Dissection with specific values (1 address) 
    """
    a = DHCP6OptPanaAuthAgent(
        b'\x00(\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 40 and a.optlen == 16 and len(a.paaaddr) == 1 and \
           a.paaaddr[0] == "2001:db8::1"


def test_DHCP6OptPanaAuthAgentInstantiationwithspecificvalues2addresses():
    """
    DHCP6OptPanaAuthAgent - Instantiation with specific values (2 addresses) 
    """
    assert raw(DHCP6OptPanaAuthAgent(paaaddr=["2001:db8::1",
                                              "2001:db8::2"])) == b'\x00(\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


def test_DHCP6OptPanaAuthAgentDissectionwithspecificvalues2addresses():
    """
    DHCP6OptPanaAuthAgent - Dissection with specific values (2 addresses) 
    """
    a = DHCP6OptPanaAuthAgent(
        b'\x00(\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 40 and a.optlen == 32 and len(a.paaaddr) == 2 and \
           a.paaaddr[0] == "2001:db8::1" and a.paaaddr[1] == "2001:db8::2"


def test_DHCP6OptNewPOSIXTimeZoneBasicInstantiation():
    """
    DHCP6OptNewPOSIXTimeZone - Basic Instantiation
    """
    assert raw(DHCP6OptNewPOSIXTimeZone()) == b'\x00)\x00\x00'


def test_DHCP6OptNewPOSIXTimeZoneBasicDissection():
    """
    DHCP6OptNewPOSIXTimeZone - Basic Dissection 
    """
    a = DHCP6OptNewPOSIXTimeZone(b'\x00)\x00\x00')
    assert a.optcode == 41 and a.optlen == 0 and a.optdata == b""


def test_DHCP6OptNewPOSIXTimeZoneInstantiationwithspecificvalues():
    """
    DHCP6OptNewPOSIXTimeZone - Instantiation with specific values 
    """
    assert raw(DHCP6OptNewPOSIXTimeZone(
        optdata="EST5EDT4,M3.2.0/02:00,M11.1.0/02:00")) == b'\x00)\x00#EST5EDT4,M3.2.0/02:00,M11.1.0/02:00'


def test_DHCP6OptNewPOSIXTimeZoneDissectionwithspecificvalues():
    """
    DHCP6OptNewPOSIXTimeZone - Dissection with specific values 
    """
    a = DHCP6OptNewPOSIXTimeZone(
        b'\x00)\x00#EST5EDT4,M3.2.0/02:00,M11.1.0/02:00')
    assert a.optcode == 41 and a.optlen == 35 and a.optdata == b"EST5EDT4,M3.2.0/02:00,M11.1.0/02:00"


def test_DHCP6OptNewTZDBTimeZoneBasicInstantiation():
    """
    DHCP6OptNewTZDBTimeZone - Basic Instantiation
    """
    assert raw(DHCP6OptNewTZDBTimeZone()) == b'\x00*\x00\x00'


def test_DHCP6OptNewTZDBTimeZoneBasicDissection():
    """
    DHCP6OptNewTZDBTimeZone - Basic Dissection 
    """
    a = DHCP6OptNewTZDBTimeZone(b'\x00*\x00\x00')
    assert a.optcode == 42 and a.optlen == 0 and a.optdata == b""


def test_DHCP6OptNewTZDBTimeZoneInstantiationwithspecificvalues():
    """
    DHCP6OptNewTZDBTimeZone - Instantiation with specific values 
    """
    assert raw(DHCP6OptNewTZDBTimeZone(
        optdata="Europe/Zurich")) == b'\x00*\x00\rEurope/Zurich'


def test_DHCP6OptNewTZDBTimeZoneDissectionwithspecificvalues():
    """
    DHCP6OptNewTZDBTimeZone - Dissection with specific values 
    """
    a = DHCP6OptNewTZDBTimeZone(b'\x00*\x00\rEurope/Zurich')
    assert a.optcode == 42 and a.optlen == 13 and a.optdata == b"Europe/Zurich"


def test_DHCP6OptRelayAgentEROBasicInstantiation():
    """
    DHCP6OptRelayAgentERO - Basic Instantiation
    """
    assert raw(DHCP6OptRelayAgentERO()) == b'\x00+\x00\x04\x00\x17\x00\x18'


def test_DHCP6OptRelayAgentEROoptlenfieldcomputation():
    """
    DHCP6OptRelayAgentERO - optlen field computation 
    """
    assert raw(DHCP6OptRelayAgentERO(reqopts=[1, 2, 3,
                                              4])) == b'\x00+\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04'


def test_DHCP6OptRelayAgentEROinstantiationwithemptylist():
    """
    DHCP6OptRelayAgentERO - instantiation with empty list 
    """
    assert raw(DHCP6OptRelayAgentERO(reqopts=[])) == b'\x00+\x00\x00'


def test_DHCP6OptRelayAgentEROBasicdissection():
    """
    DHCP6OptRelayAgentERO - Basic dissection 
    """
    a = DHCP6OptRelayAgentERO(b'\x00+\x00\x00')
    assert a.optcode == 43 and a.optlen == 0 and a.reqopts == [23, 24]


def test_DHCP6OptRelayAgentERODissectionwithspecificvalue():
    """
    DHCP6OptRelayAgentERO - Dissection with specific value 
    """
    a = DHCP6OptRelayAgentERO(b'\x00+\x00\x08\x00\x01\x00\x02\x00\x03\x00\x04')
    assert a.optcode == 43 and a.optlen == 8 and a.reqopts == [1, 2, 3, 4]


def test_DHCP6OptLQClientLinkBasicInstantiation():
    """
    DHCP6OptLQClientLink - Basic Instantiation
    """
    assert raw(DHCP6OptLQClientLink()) == b'\x000\x00\x00'


def test_DHCP6OptLQClientLinkBasicDissection():
    """
    DHCP6OptLQClientLink - Basic Dissection 
    """
    a = DHCP6OptLQClientLink(b"\x000\x00\x00")
    assert a.optcode == 48 and a.optlen == 0 and a.linkaddress == []


def test_DHCP6OptLQClientLinkInstantiationwithspecificvalues1address():
    """
    DHCP6OptLQClientLink - Instantiation with specific values (1 address) 
    """
    assert raw(DHCP6OptLQClientLink(linkaddress=[
        "2001:db8::1"])) == b'\x000\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def test_DHCP6OptLQClientLinkDissectionwithspecificvalues1address():
    """
    DHCP6OptLQClientLink - Dissection with specific values (1 address) 
    """
    a = DHCP6OptLQClientLink(
        b'\x000\x00\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
    assert a.optcode == 48 and a.optlen == 16 and len(a.linkaddress) == 1 and \
           a.linkaddress[0] == "2001:db8::1"


def test_DHCP6OptLQClientLinkInstantiationwithspecificvalues2addresses():
    """
    DHCP6OptLQClientLink - Instantiation with specific values (2 addresses) 
    """
    assert raw(DHCP6OptLQClientLink(linkaddress=["2001:db8::1",
                                                 "2001:db8::2"])) == b'\x000\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'


def test_DHCP6OptLQClientLinkDissectionwithspecificvalues2addresses():
    """
    DHCP6OptLQClientLink - Dissection with specific values (2 addresses) 
    """
    a = DHCP6OptLQClientLink(
        b'\x000\x00  \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
    assert a.optcode == 48 and a.optlen == 32 and len(a.linkaddress) == 2 and \
           a.linkaddress[0] == "2001:db8::1" and a.linkaddress[
               1] == "2001:db8::2"


def test_DHCP6OptBootFileUrlBasicInstantiation():
    """
    DHCP6OptBootFileUrl - Basic Instantiation
    """
    assert raw(DHCP6OptBootFileUrl()) == b'\x00;\x00\x00'


def test_DHCP6OptBootFileUrlBasicDissection():
    """
    DHCP6OptBootFileUrl - Basic Dissection 
    """
    a = DHCP6OptBootFileUrl(b'\x00;\x00\x00')
    assert a.optcode == 59 and a.optlen == 0 and a.optdata == b""


def test_DHCP6OptBootFileUrlInstantiationwithspecificvalues():
    """
    DHCP6OptBootFileUrl - Instantiation with specific values 
    """
    assert raw(DHCP6OptBootFileUrl(
        optdata="http://wp.pl/file")) == b'\x00;\x00\x11http://wp.pl/file'


def test_DHCP6OptBootFileUrlDissectionwithspecificvalues():
    """
    DHCP6OptBootFileUrl - Dissection with specific values 
    """
    a = DHCP6OptBootFileUrl(b'\x00;\x00\x11http://wp.pl/file')
    assert a.optcode == 59 and a.optlen == 17 and a.optdata == b"http://wp.pl/file"


def test_DHCP6OptClientArchTypeBasicInstantiation():
    """
    DHCP6OptClientArchType - Basic Instantiation
    """
    raw(DHCP6OptClientArchType())
    assert raw(DHCP6OptClientArchType()) == b'\x00=\x00\x00'


def test_DHCP6OptClientArchTypeBasicDissection():
    """
    DHCP6OptClientArchType - Basic Dissection 
    """
    a = DHCP6OptClientArchType(b'\x00=\x00\x00')
    assert a.optcode == 61 and a.optlen == 0 and a.archtypes == []


def test_DHCP6OptClientArchTypeInstantiationwithspecificvalueasjustint():
    """
    DHCP6OptClientArchType - Instantiation with specific value as just int 
    """
    assert raw(DHCP6OptClientArchType(archtypes=7)) == b'\x00=\x00\x02\x00\x07'


def test_DHCP6OptClientArchTypeInstantiationwithspecificvalueassingleitemlistofint():
    """
    DHCP6OptClientArchType - Instantiation with specific value as single item list of int 
    """
    assert raw(
        DHCP6OptClientArchType(archtypes=[7])) == b'\x00=\x00\x02\x00\x07'


def test_DHCP6OptClientArchTypeDissectionwithspecific1valuelist():
    """
    DHCP6OptClientArchType - Dissection with specific 1 value list 
    """
    a = DHCP6OptClientArchType(b'\x00=\x00\x02\x00\x07')
    assert a.optcode == 61 and a.optlen == 2 and a.archtypes == [7]


def test_DHCP6OptClientArchTypeInstantiationwithspecificvalueas2itemlistofint():
    """
    DHCP6OptClientArchType - Instantiation with specific value as 2 item list of int 
    """
    assert raw(DHCP6OptClientArchType(
        archtypes=[7, 9])) == b'\x00=\x00\x04\x00\x07\x00\x09'


def test_DHCP6OptClientArchTypeDissectionwithspecific2valueslist():
    """
    DHCP6OptClientArchType - Dissection with specific 2 values list 
    """
    a = DHCP6OptClientArchType(b'\x00=\x00\x04\x00\x07\x00\x09')
    assert a.optcode == 61 and a.optlen == 4 and a.archtypes == [7, 9]


def test_DHCP6OptClientNetworkInterIdBasicInstantiation():
    """
    DHCP6OptClientNetworkInterId - Basic Instantiation
    """
    raw(DHCP6OptClientNetworkInterId())
    assert raw(DHCP6OptClientNetworkInterId()) == b'\x00>\x00\x03\x00\x00\x00'


def test_DHCP6OptClientNetworkInterIdBasicDissection():
    """
    DHCP6OptClientNetworkInterId - Basic Dissection 
    """
    a = DHCP6OptClientNetworkInterId(b'\x00>\x00\x03\x00\x00\x00')
    assert a.optcode == 62 and a.optlen == 3 and a.iitype == 0 and a.iimajor == 0 and a.iiminor == 0


def test_DHCP6OptClientNetworkInterIdInstantiationwithspecificvalues():
    """
    DHCP6OptClientNetworkInterId - Instantiation with specific values 
    """
    assert raw(DHCP6OptClientNetworkInterId(iitype=1, iimajor=2,
                                            iiminor=3)) == b'\x00>\x00\x03\x01\x02\x03'


def test_DHCP6OptClientNetworkInterIdDissectionwithspecificvalues():
    """
    DHCP6OptClientNetworkInterId - Dissection with specific values 
    """
    a = DHCP6OptClientNetworkInterId(b'\x00>\x00\x03\x01\x02\x03')
    assert a.optcode == 62 and a.optlen == 3 and a.iitype == 1 and a.iimajor == 2 and a.iiminor == 3


def test_DHCP6OptERPDomainBasicInstantiation():
    """
    DHCP6OptERPDomain - Basic Instantiation
    """
    assert raw(DHCP6OptERPDomain()) == b'\x00A\x00\x00'


def test_DHCP6OptERPDomainBasicDissection():
    """
    DHCP6OptERPDomain - Basic Dissection 
    """
    a = DHCP6OptERPDomain(b'\x00A\x00\x00')
    assert a.optcode == 65 and a.optlen == 0 and a.erpdomain == []


def test_DHCP6OptERPDomainInstantiationwithspecificvalues1domain():
    """
    DHCP6OptERPDomain - Instantiation with specific values (1 domain) 
    """
    assert raw(DHCP6OptERPDomain(erpdomain=[
        "toto.example.com."])) == b'\x00A\x00\x12\x04toto\x07example\x03com\x00'


def test_DHCP6OptERPDomainDissectionwithspecificvalues1domain():
    """
    DHCP6OptERPDomain - Dissection with specific values (1 domain) 
    """
    a = DHCP6OptERPDomain(b'\x00A\x00\x12\x04toto\x07example\x03com\x00')
    assert a.optcode == 65 and a.optlen == 18 and len(a.erpdomain) == 1 and \
           a.erpdomain[0] == "toto.example.com."


def test_DHCP6OptERPDomainInstantiationwithspecificvalues2domains():
    """
    DHCP6OptERPDomain - Instantiation with specific values (2 domains) 
    """
    assert raw(DHCP6OptERPDomain(erpdomain=["toto.example.com.",
                                            "titi.example.com."])) == b'\x00A\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00'


def test_DHCP6OptERPDomainDissectionwithspecificvalues2domains():
    """
    DHCP6OptERPDomain - Dissection with specific values (2 domains) 
    """
    a = DHCP6OptERPDomain(
        b'\x00A\x00$\x04toto\x07example\x03com\x00\x04titi\x07example\x03com\x00')
    assert a.optcode == 65 and a.optlen == 36 and len(a.erpdomain) == 2 and \
           a.erpdomain[0] == "toto.example.com." and a.erpdomain[
               1] == "titi.example.com."


def test_DHCP6OptRelaySuppliedOptBasicInstantiation():
    """
    DHCP6OptRelaySuppliedOpt - Basic Instantiation
    """
    assert raw(DHCP6OptRelaySuppliedOpt()) == b'\x00B\x00\x00'


def test_DHCP6OptRelaySuppliedOptBasicDissection():
    """
    DHCP6OptRelaySuppliedOpt - Basic Dissection 
    """
    a = DHCP6OptRelaySuppliedOpt(b'\x00B\x00\x00')
    assert a.optcode == 66 and a.optlen == 0 and a.relaysupplied == []


def test_DHCP6OptRelaySuppliedOptInstantiationwithspecificvalues():
    """
    DHCP6OptRelaySuppliedOpt - Instantiation with specific values 
    """
    assert raw(DHCP6OptRelaySuppliedOpt(relaysupplied=DHCP6OptERPDomain(
        erpdomain=[
            "toto.example.com."]))) == b'\x00B\x00\x16\x00A\x00\x12\x04toto\x07example\x03com\x00'


def test_DHCP6OptRelaySuppliedOptDissectionwithspecificvalues():
    """
    DHCP6OptRelaySuppliedOpt - Dissection with specific values 
    """
    a = DHCP6OptRelaySuppliedOpt(
        b'\x00B\x00\x16\x00A\x00\x12\x04toto\x07example\x03com\x00')
    assert a.optcode == 66 and a.optlen == 22 and len(
        a.relaysupplied) == 1 and isinstance(a.relaysupplied[0],
                                             DHCP6OptERPDomain) and \
           a.relaysupplied[0].erpdomain[0] == "toto.example.com."


def test_Basicbuilddissect():
    """
    Basic build & dissect
    """
    s = raw(DHCP6OptClientLinkLayerAddr())
    assert (s == b"\x00O\x00\x08\x00\x01\x00\x00\x00\x00\x00\x00")
    p = DHCP6OptClientLinkLayerAddr(s)
    assert (p.clladdr == "00:00:00:00:00:00")
    r = b"\x00O\x00\x08\x00\x01\x00\x01\x02\x03\x04\x05"
    p = DHCP6OptClientLinkLayerAddr(r)
    assert (p.clladdr == "00:01:02:03:04:05")


def test_Basicbuilddissect1():
    """
    Basic build & dissect
    """
    s = raw(DHCP6OptVSS())
    assert (s == b"\x00D\x00\x01\xff")
    p = DHCP6OptVSS(s)
    assert (p.type == 255)


def test_DHCP6SolicitBasicInstantiation():
    """
    DHCP6_Solicit - Basic Instantiation
    """
    assert raw(DHCP6_Solicit()) == b'\x01\x00\x00\x00'


def test_DHCP6SolicitBasicDissection():
    """
    DHCP6_Solicit - Basic Dissection 
    """
    a = DHCP6_Solicit(b'\x01\x00\x00\x00')
    assert a.msgtype == 1 and a.trid == 0


def test_DHCP6SolicitBasictestofDHCP6solicithashret():
    """
    DHCP6_Solicit - Basic test of DHCP6_solicit.hashret() 
    """
    assert DHCP6_Solicit().hashret() == b'\x00\x00\x00'


def test_DHCP6SolicitTestofDHCP6solicithashretwithspecificvalues():
    """
    DHCP6_Solicit - Test of DHCP6_solicit.hashret() with specific values 
    """
    assert DHCP6_Solicit(trid=0xbbccdd).hashret() == b'\xbb\xcc\xdd'


def test_DHCP6SolicitUDPportsoverload():
    """
    DHCP6_Solicit - UDP ports overload 
    """
    a = UDP() / DHCP6_Solicit()
    assert a.sport == 546 and a.dport == 547


def test_DHCP6SolicitDispatchbasedonUDPport():
    """
    DHCP6_Solicit - Dispatch based on UDP port 
    """
    a = UDP(raw(UDP() / DHCP6_Solicit()))
    isinstance(a.payload, DHCP6_Solicit)


def test_DHCP6AdvertiseBasicInstantiation():
    """
    DHCP6_Advertise - Basic Instantiation
    """
    assert raw(DHCP6_Advertise()) == b'\x02\x00\x00\x00'


def test_DHCP6AdvertiseBasictestofDHCP6solicithashret():
    """
    DHCP6_Advertise - Basic test of DHCP6_solicit.hashret() 
    """
    assert DHCP6_Advertise().hashret() == b'\x00\x00\x00'


def test_DHCP6AdvertiseTestofDHCP6Advertisehashretwithspecificvalues():
    """
    DHCP6_Advertise - Test of DHCP6_Advertise.hashret() with specific values 
    """
    assert DHCP6_Advertise(trid=0xbbccdd).hashret() == b'\xbb\xcc\xdd'


def test_DHCP6AdvertiseBasictestofanswerswithsolicitmessage():
    """
    DHCP6_Advertise - Basic test of answers() with solicit message 
    """
    a = DHCP6_Solicit()
    b = DHCP6_Advertise()
    assert a > b


def test_DHCP6AdvertiseTestofanswerswithsolicitmessage():
    """
    DHCP6_Advertise - Test of answers() with solicit message 
    """
    a = DHCP6_Solicit(trid=0xbbccdd)
    b = DHCP6_Advertise(trid=0xbbccdd)
    assert a > b


def test_DHCP6AdvertiseUDPportsoverload():
    """
    DHCP6_Advertise - UDP ports overload 
    """
    a = UDP() / DHCP6_Advertise()
    assert a.sport == 547 and a.dport == 546


def test_DHCP6RequestBasicInstantiation():
    """
    DHCP6_Request - Basic Instantiation
    """
    assert raw(DHCP6_Request()) == b'\x03\x00\x00\x00'


def test_DHCP6RequestBasicDissection():
    """
    DHCP6_Request - Basic Dissection 
    """
    a = DHCP6_Request(b'\x03\x00\x00\x00')
    assert a.msgtype == 3 and a.trid == 0


def test_DHCP6RequestUDPportsoverload():
    """
    DHCP6_Request - UDP ports overload 
    """
    a = UDP() / DHCP6_Request()
    assert a.sport == 546 and a.dport == 547


def test_DHCP6ConfirmBasicInstantiation():
    """
    DHCP6_Confirm - Basic Instantiation
    """
    assert raw(DHCP6_Confirm()) == b'\x04\x00\x00\x00'


def test_DHCP6ConfirmBasicDissection():
    """
    DHCP6_Confirm - Basic Dissection 
    """
    a = DHCP6_Confirm(b'\x04\x00\x00\x00')
    assert a.msgtype == 4 and a.trid == 0


def test_DHCP6ConfirmUDPportsoverload():
    """
    DHCP6_Confirm - UDP ports overload 
    """
    a = UDP() / DHCP6_Confirm()
    assert a.sport == 546 and a.dport == 547


def test_DHCP6RenewBasicInstantiation():
    """
    DHCP6_Renew - Basic Instantiation
    """
    assert raw(DHCP6_Renew()) == b'\x05\x00\x00\x00'


def test_DHCP6RenewBasicDissection():
    """
    DHCP6_Renew - Basic Dissection 
    """
    a = DHCP6_Renew(b'\x05\x00\x00\x00')
    assert a.msgtype == 5 and a.trid == 0


def test_DHCP6RenewUDPportsoverload():
    """
    DHCP6_Renew - UDP ports overload 
    """
    a = UDP() / DHCP6_Renew()
    assert a.sport == 546 and a.dport == 547


def test_DHCP6RebindBasicInstantiation():
    """
    DHCP6_Rebind - Basic Instantiation
    """
    assert raw(DHCP6_Rebind()) == b'\x06\x00\x00\x00'


def test_DHCP6RebindBasicDissection():
    """
    DHCP6_Rebind - Basic Dissection 
    """
    a = DHCP6_Rebind(b'\x06\x00\x00\x00')
    assert a.msgtype == 6 and a.trid == 0


def test_DHCP6RebindUDPportsoverload():
    """
    DHCP6_Rebind - UDP ports overload 
    """
    a = UDP() / DHCP6_Rebind()
    assert a.sport == 546 and a.dport == 547


def test_DHCP6ReplyBasicInstantiation():
    """
    DHCP6_Reply - Basic Instantiation
    """
    assert raw(DHCP6_Reply()) == b'\x07\x00\x00\x00'


def test_DHCP6ReplyBasicDissection():
    """
    DHCP6_Reply - Basic Dissection 
    """
    a = DHCP6_Reply(b'\x07\x00\x00\x00')
    assert a.msgtype == 7 and a.trid == 0


def test_DHCP6ReplyUDPportsoverload():
    """
    DHCP6_Reply - UDP ports overload 
    """
    a = UDP() / DHCP6_Reply()
    assert a.sport == 547 and a.dport == 546


def test_DHCP6ReplyAnswers():
    """
    DHCP6_Reply - Answers 
    """
    assert not DHCP6_Reply(trid=0).answers(DHCP6_Request(trid=1))
    assert DHCP6_Reply(trid=1).answers(DHCP6_Request(trid=1))


def test_DHCP6ReleaseBasicInstantiation():
    """
    DHCP6_Release - Basic Instantiation
    """
    assert raw(DHCP6_Release()) == b'\x08\x00\x00\x00'


def test_DHCP6ReleaseBasicDissection():
    """
    DHCP6_Release - Basic Dissection 
    """
    a = DHCP6_Release(b'\x08\x00\x00\x00')
    assert a.msgtype == 8 and a.trid == 0


def test_DHCP6ReleaseUDPportsoverload():
    """
    DHCP6_Release - UDP ports overload 
    """
    a = UDP() / DHCP6_Release()
    assert a.sport == 546 and a.dport == 547


def test_DHCP6DeclineBasicInstantiation():
    """
    DHCP6_Decline - Basic Instantiation
    """
    assert raw(DHCP6_Decline()) == b'\x09\x00\x00\x00'


def test_DHCP6ConfirmBasicDissection1():
    """
    DHCP6_Confirm - Basic Dissection 
    """
    a = DHCP6_Confirm(b'\x09\x00\x00\x00')
    assert a.msgtype == 9 and a.trid == 0


def test_DHCP6DeclineUDPportsoverload():
    """
    DHCP6_Decline - UDP ports overload 
    """
    a = UDP() / DHCP6_Decline()
    assert a.sport == 546 and a.dport == 547


def test_DHCP6ReconfBasicInstantiation():
    """
    DHCP6_Reconf - Basic Instantiation
    """
    assert raw(DHCP6_Reconf()) == b'\x0A\x00\x00\x00'


def test_DHCP6ReconfBasicDissection():
    """
    DHCP6_Reconf - Basic Dissection 
    """
    a = DHCP6_Reconf(b'\x0A\x00\x00\x00')
    assert a.msgtype == 10 and a.trid == 0


def test_DHCP6ReconfUDPportsoverload():
    """
    DHCP6_Reconf - UDP ports overload 
    """
    a = UDP() / DHCP6_Reconf()
    assert a.sport == 547 and a.dport == 546


def test_DHCP6InfoRequestBasicInstantiation():
    """
    DHCP6_InfoRequest - Basic Instantiation
    """
    assert raw(DHCP6_InfoRequest()) == b'\x0B\x00\x00\x00'


def test_DHCP6InfoRequestBasicDissection():
    """
    DHCP6_InfoRequest - Basic Dissection 
    """
    a = DHCP6_InfoRequest(b'\x0B\x00\x00\x00')
    assert a.msgtype == 11 and a.trid == 0


def test_DHCP6InfoRequestUDPportsoverload():
    """
    DHCP6_InfoRequest - UDP ports overload 
    """
    a = UDP() / DHCP6_InfoRequest()
    assert a.sport == 546 and a.dport == 547


def test_DHCP6RelayForwardBasicInstantiation():
    """
    DHCP6_RelayForward - Basic Instantiation
    """
    assert raw(
        DHCP6_RelayForward()) == b'\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DHCP6RelayForwardBasicDissection():
    """
    DHCP6_RelayForward - Basic Dissection 
    """
    a = DHCP6_RelayForward(
        b'\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.msgtype == 12 and a.hopcount == 0 and a.linkaddr == "::" and a.peeraddr == "::"


def test_DHCP6RelayForwardDissectionwithoptions():
    """
    DHCP6_RelayForward - Dissection with options 
    """
    a = DHCP6_RelayForward(
        b'\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x04\x03\x01\x00\x00')
    assert a.msgtype == 12 and DHCP6OptRelayMsg in a and isinstance(a.message,
                                                                    DHCP6_Request)


def test_DHCP6RelayForwardAdvanceddissection():
    """
    DHCP6_RelayForward - Advanced dissection 
    """
    s = b'`\x00\x00\x00\x002\x11@\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x02#\x02#\x002\xf0\xaf\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x04\x01\x00\x00\x00'
    p = IPv6(s)
    assert DHCP6OptRelayMsg in p and isinstance(p.message, DHCP6_Solicit)


def test_DHCP6OptRelayMsgBasicInstantiation():
    """
    DHCP6OptRelayMsg - Basic Instantiation
    """
    assert raw(DHCP6OptRelayMsg(optcode=37)) == b'\x00%\x00\x04\x00\x00\x00\x00'


def test_DHCP6OptRelayMsgBasicDissection():
    """
    DHCP6OptRelayMsg - Basic Dissection 
    """
    a = DHCP6OptRelayMsg(b'\x00\r\x00\x00')
    assert a.optcode == 13 and a.optlen == 0 and isinstance(a.message, DHCP6)


def test_DHCP6OptRelayMsgEmbeddedDHCP6packetInstantiation():
    """
    DHCP6OptRelayMsg - Embedded DHCP6 packet Instantiation 
    """
    assert raw(DHCP6OptRelayMsg(
        message=DHCP6_Solicit())) == b'\x00\t\x00\x04\x01\x00\x00\x00'


def test_DHCP6OptRelayMsgEmbeddedDHCP6packetDissection():
    """
    DHCP6OptRelayMsg - Embedded DHCP6 packet Dissection 
    """
    p = DHCP6OptRelayMsg(b'\x00\t\x00\x04\x01\x00\x00\x00')
    assert isinstance(p.message, DHCP6_Solicit)


def test_DHCP6RelayReplyBasicInstantiation():
    """
    DHCP6_RelayReply - Basic Instantiation
    """
    assert raw(
        DHCP6_RelayReply()) == b'\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_DHCP6RelayReplyBasicDissection():
    """
    DHCP6_RelayReply - Basic Dissection 
    """
    a = DHCP6_RelayReply(
        b'\r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert a.msgtype == 13 and a.hopcount == 0 and a.linkaddr == "::" and a.peeraddr == "::"
