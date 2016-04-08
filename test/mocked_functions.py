"""
Test functions mocking outputs
"""

import mock
import StringIO

from scapy.arch.unix import read_routes6, in6_getifaddr
from scapy.data import IPV6_ADDR_LOOPBACK, IPV6_ADDR_LINKLOCAL
from scapy.utils6 import in6_isvalid, in6_islladdr


def valid_output_read_routes6(routes):
    """"Return True if 'routes' contains correctly formatted entries, False
        otherwise"""

    for destination, plen, next_hop, dev, cset  in routes:
        if not in6_isvalid(destination) or not type(plen) == int:
            return False
        if not in6_isvalid(next_hop) or not type(dev) == str:
            return False
        for address in cset:
            if not in6_isvalid(address):
                return False

    return True


def check_mandatory_ipv6_routes(routes6):
    """Ensure that mandatory IPv6 routes are present"""

    if len(filter(lambda r: r[0] == "::1" and r[-1] == ["::1"], routes6)) < 1:
        return False

    if len(filter(lambda r: r[0] == "fe80::" and r[1] == 64, routes6)) < 1:
        return False

    if len(filter(lambda r: in6_islladdr(r[0]) and r[1] == 128 and \
            r[-1] == ["::1"], routes6)) < 1:
        return False

    return True


@mock.patch("scapy.arch.unix.in6_getifaddr")
@mock.patch("scapy.arch.unix.os")
def test_osx_10_10_4(mock_os, mock_in6_getifaddr):
    """Test read_routes6() on OS X 10.10.4"""

    # 'netstat -rn -f inet6' output
    netstat_output = """
Routing tables

Internet6:
Destination                             Gateway                         Flags         Netif Expire
::1                                     ::1                             UHL             lo0
fe80::%lo0/64                           fe80::1%lo0                     UcI             lo0
fe80::1%lo0                             link#1                          UHLI            lo0
fe80::%en0/64                           link#4                          UCI             en0
fe80::a00:27ff:fe9b:c965%en0            8:0:27:9b:c9:65                 UHLI            lo0
ff01::%lo0/32                           ::1                             UmCI            lo0
ff01::%en0/32                           link#4                          UmCI            en0
ff02::%lo0/32                           ::1                             UmCI            lo0
ff02::%en0/32                           link#4                          UmCI            en0
"""

    # Mocked file descriptor
    strio = StringIO.StringIO(netstat_output)
    mock_os.popen = mock.MagicMock(return_value=strio)
    
    # Mocked in6_getifaddr() output
    mock_in6_getifaddr.return_value = [("::1", IPV6_ADDR_LOOPBACK, "lo0"),
                                       ("fe80::a00:27ff:fe9b:c965", IPV6_ADDR_LINKLOCAL, "en0")]

    # Test the function
    routes = read_routes6()
    print netstat_output
    for r in routes:
        print r
    assert(len(routes) == 5)
    assert(check_mandatory_ipv6_routes(routes))


@mock.patch("scapy.arch.unix.in6_getifaddr")
@mock.patch("scapy.arch.unix.os")
def test_osx_10_9_5(mock_os, mock_in6_getifaddr):
    """Test read_routes6() on OS X 10.9.5"""

    # 'netstat -rn -f inet6' output
    netstat_output = """
Routing tables

Internet6:
Destination                             Gateway                         Flags         Netif Expire
::1                                     ::1                             UHL             lo0
fe80::%lo0/64                           fe80::1%lo0                     UcI             lo0
fe80::1%lo0                             link#1                          UHLI            lo0
fe80::%en0/64                           link#4                          UCI             en0
fe80::ba26:6cff:fe5f:4eee%en0           b8:26:6c:5f:4e:ee               UHLWIi          en0
fe80::bae8:56ff:fe45:8ce6%en0           b8:e8:56:45:8c:e6               UHLI            lo0
ff01::%lo0/32                           ::1                             UmCI            lo0
ff01::%en0/32                           link#4                          UmCI            en0
ff02::%lo0/32                           ::1                             UmCI            lo0
ff02::%en0/32                           link#4                          UmCI            en0
"""

    # Mocked file descriptor
    strio = StringIO.StringIO(netstat_output)
    mock_os.popen = mock.MagicMock(return_value=strio)
    
    # Mocked in6_getifaddr() output
    mock_in6_getifaddr.return_value = [("::1", IPV6_ADDR_LOOPBACK, "lo0"),
                                       ("fe80::ba26:6cff:fe5f:4eee", IPV6_ADDR_LINKLOCAL, "en0")]

    # Test the function
    routes = read_routes6()
    print netstat_output
    for r in routes:
        print r
    assert(len(routes) == 6)
    assert(check_mandatory_ipv6_routes(routes))


@mock.patch("scapy.arch.unix.in6_getifaddr")
@mock.patch("scapy.arch.unix.os")
def test_osx_10_9_5_global(mock_os, mock_in6_getifaddr):
    """Test read_routes6() on OS X 10.9.5 with an IPv6 connectivity"""

    # 'netstat -rn -f inet6' output
    netstat_output = """
Routing tables

Internet6:
Destination                             Gateway                         Flags         Netif Expire
default                                 fe80::ba26:8aff:fe5f:4eef%en0   UGc             en0
::1                                     ::1                             UHL             lo0
2a01:ab09:7d:1f01::/64                  link#4                          UC              en0
2a01:ab09:7d:1f01:420:205c:9fab:5be7    b8:e9:55:44:7c:e5               UHL             lo0
2a01:ab09:7d:1f01:ba26:8aff:fe5f:4eef   b8:26:8a:5f:4e:ef               UHLWI           en0
2a01:ab09:7d:1f01:bae9:55ff:fe44:7ce5   b8:e9:55:44:7c:e5               UHL             lo0
fe80::%lo0/64                           fe80::1%lo0                     UcI             lo0
fe80::1%lo0                             link#1                          UHLI            lo0
fe80::%en0/64                           link#4                          UCI             en0
fe80::5664:d9ff:fe79:4e00%en0           54:64:d9:79:4e:0                UHLWI           en0
fe80::6ead:f8ff:fe74:945a%en0           6c:ad:f8:74:94:5a               UHLWI           en0
fe80::a2f3:c1ff:fec4:5b50%en0           a0:f3:c1:c4:5b:50               UHLWI           en0
fe80::ba26:8aff:fe5f:4eef%en0           b8:26:8a:5f:4e:ef               UHLWIir         en0
fe80::bae9:55ff:fe44:7ce5%en0           b8:e9:55:44:7c:e5               UHLI            lo0
ff01::%lo0/32                           ::1                             UmCI            lo0
ff01::%en0/32                           link#4                          UmCI            en0
ff02::%lo0/32                           ::1                             UmCI            lo
"""

    # Mocked file descriptor
    strio = StringIO.StringIO(netstat_output)
    mock_os.popen = mock.MagicMock(return_value=strio)

    # Mocked in6_getifaddr() output
    mock_in6_getifaddr.return_value = [("::1", IPV6_ADDR_LOOPBACK, "lo0"),
                                       ("fe80::ba26:6cff:fe5f:4eee", IPV6_ADDR_LINKLOCAL, "en0")]

    # Test the function
    routes = read_routes6()
    assert(valid_output_read_routes6(routes))

    for r in routes:
        print r
    assert(len(routes) == 11)
    assert(check_mandatory_ipv6_routes(routes))


@mock.patch("scapy.arch.unix.in6_getifaddr")
@mock.patch("scapy.arch.unix.os")
def test_freebsd_10_2(mock_os, mock_in6_getifaddr):
    """Test read_routes6() on FreeBSD 10.2"""

    # 'netstat -rn -f inet6' output
    netstat_output = """
Routing tables

Internet6:
Destination                       Gateway                       Flags      Netif Expire
::/96                             ::1                           UGRS        lo0
::1                               link#2                        UH          lo0
::ffff:0.0.0.0/96                 ::1                           UGRS        lo0
fe80::/10                         ::1                           UGRS        lo0
fe80::%lo0/64                     link#2                        U           lo0
fe80::1%lo0                       link#2                        UHS         lo0
ff01::%lo0/32                     ::1                           U           lo0
ff02::/16                         ::1                           UGRS        lo0
ff02::%lo0/32                     ::1                           U           lo0
"""

    # Mocked file descriptor
    strio = StringIO.StringIO(netstat_output)
    mock_os.popen = mock.MagicMock(return_value=strio)
    
    # Mocked in6_getifaddr() output
    mock_in6_getifaddr.return_value = [("::1", IPV6_ADDR_LOOPBACK, "lo0")]

    # Test the function
    routes = read_routes6()
    print netstat_output
    for r in routes:
        print r
    assert(len(routes) == 3)
    assert(check_mandatory_ipv6_routes(routes))


@mock.patch("scapy.arch.OPENBSD")
@mock.patch("scapy.arch.unix.in6_getifaddr")
@mock.patch("scapy.arch.unix.os")
def test_openbsd_5_5(mock_os, mock_in6_getifaddr, mock_openbsd):
    """Test read_routes6() on OpenBSD 5.5"""

    # 'netstat -rn -f inet6' output
    netstat_output = """
Routing tables

Internet6:
Destination                        Gateway                        Flags   Refs      Use   Mtu  Prio Iface
::/104                             ::1                            UGRS       0        0     -     8 lo0  
::/96                              ::1                            UGRS       0        0     -     8 lo0  
::1                                ::1                            UH        14        0 33144     4 lo0  
::127.0.0.0/104                    ::1                            UGRS       0        0     -     8 lo0  
::224.0.0.0/100                    ::1                            UGRS       0        0     -     8 lo0  
::255.0.0.0/104                    ::1                            UGRS       0        0     -     8 lo0  
::ffff:0.0.0.0/96                  ::1                            UGRS       0        0     -     8 lo0  
2002::/24                          ::1                            UGRS       0        0     -     8 lo0  
2002:7f00::/24                     ::1                            UGRS       0        0     -     8 lo0  
2002:e000::/20                     ::1                            UGRS       0        0     -     8 lo0  
2002:ff00::/24                     ::1                            UGRS       0        0     -     8 lo0  
fe80::/10                          ::1                            UGRS       0        0     -     8 lo0  
fe80::%em0/64                      link#1                         UC         0        0     -     4 em0  
fe80::a00:27ff:fe04:59bf%em0       08:00:27:04:59:bf              UHL        0        0     -     4 lo0  
fe80::%lo0/64                      fe80::1%lo0                    U          0        0     -     4 lo0  
fe80::1%lo0                        link#3                         UHL        0        0     -     4 lo0  
fec0::/10                          ::1                            UGRS       0        0     -     8 lo0  
ff01::/16                          ::1                            UGRS       0        0     -     8 lo0  
ff01::%em0/32                      link#1                         UC         0        0     -     4 em0  
ff01::%lo0/32                      fe80::1%lo0                    UC         0        0     -     4 lo0  
ff02::/16                          ::1                            UGRS       0        0     -     8 lo0  
ff02::%em0/32                      link#1                         UC         0        0     -     4 em0  
ff02::%lo0/32                      fe80::1%lo0                    UC         0        0     -     4 lo0 
"""

    # Mocked file descriptor
    strio = StringIO.StringIO(netstat_output)
    mock_os.popen = mock.MagicMock(return_value=strio)
    
    # Mocked in6_getifaddr() output
    mock_in6_getifaddr.return_value = [("::1", IPV6_ADDR_LOOPBACK, "lo0"),
                                       ("fe80::a00:27ff:fe04:59bf", IPV6_ADDR_LINKLOCAL, "em0")]

    # Mocked OpenBSD parsing behavior
    mock_openbsd = True

    # Test the function
    routes = read_routes6()
    for r in routes:
        print r
    assert(len(routes) == 5)
    assert(check_mandatory_ipv6_routes(routes))


@mock.patch("scapy.arch.NETBSD")
@mock.patch("scapy.arch.unix.in6_getifaddr")
@mock.patch("scapy.arch.unix.os")
def test_netbsd_7_0(mock_os, mock_in6_getifaddr, mock_netbsd):
    """Test read_routes6() on NetBSD 7.0"""

    # 'netstat -rn -f inet6' output
    netstat_output = """
Routing tables

Internet6:
Destination                        Gateway                        Flags    Refs      Use    Mtu Interface
::/104                             ::1                            UGRS        -        -      -  lo0
::/96                              ::1                            UGRS        -        -      -  lo0
::1                                ::1                            UH          -        -  33648  lo0
::127.0.0.0/104                    ::1                            UGRS        -        -      -  lo0
::224.0.0.0/100                    ::1                            UGRS        -        -      -  lo0
::255.0.0.0/104                    ::1                            UGRS        -        -      -  lo0
::ffff:0.0.0.0/96                  ::1                            UGRS        -        -      -  lo0
2001:db8::/32                      ::1                            UGRS        -        -      -  lo0
2002::/24                          ::1                            UGRS        -        -      -  lo0
2002:7f00::/24                     ::1                            UGRS        -        -      -  lo0
2002:e000::/20                     ::1                            UGRS        -        -      -  lo0
2002:ff00::/24                     ::1                            UGRS        -        -      -  lo0
fe80::/10                          ::1                            UGRS        -        -      -  lo0
fe80::%wm0/64                      link#1                         UC          -        -      -  wm0
fe80::acd1:3989:180e:fde0          08:00:27:a1:64:d8              UHL         -        -      -  lo0
fe80::%lo0/64                      fe80::1                        U           -        -      -  lo0
fe80::1                            link#2                         UHL         -        -      -  lo0
ff01:1::/32                        link#1                         UC          -        -      -  wm0
ff01:2::/32                        ::1                            UC          -        -      -  lo0
ff02::%wm0/32                      link#1                         UC          -        -      -  wm0
ff02::%lo0/32                      ::1                            UC          -        -      -  lo0
"""

    # Mocked file descriptor
    strio = StringIO.StringIO(netstat_output)
    mock_os.popen = mock.MagicMock(return_value=strio)
    
    # Mocked in6_getifaddr() output
    mock_in6_getifaddr.return_value = [("::1", IPV6_ADDR_LOOPBACK, "lo0"),
                                       ("fe80::acd1:3989:180e:fde0", IPV6_ADDR_LINKLOCAL, "wm0")]

    # Test the function
    routes = read_routes6()
    print netstat_output
    for r in routes:
        print r
    assert(len(routes) == 5)
    assert(check_mandatory_ipv6_routes(routes))
