# This file is part of Scapy
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury
# This program is published under a GPLv2 license

"""
This is a register for DH groups from RFC 3526 and RFC 4306.
At this time the groups from RFC 7919 have not been registered by openssl,
thus they cannot be imported from the cryptography library.

We also provide TLS identifiers for these DH groups and also the ECDH groups.
(Note that the equivalent of _ffdh_groups for ECDH is ec._CURVE_TYPES.)
"""

from __future__ import absolute_import

from scapy.config import conf
from scapy.error import warning
from scapy.utils import long_converter
import scapy.modules.six as six
if conf.crypto_valid:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import dh, ec
    from cryptography.hazmat.primitives import serialization
if conf.crypto_valid_advanced:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.asymmetric import x448

# We have to start by a dirty hack in order to allow long generators,
# which some versions of openssl love to use...

if conf.crypto_valid:
    from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers

    try:
        # We test with dummy values whether the size limitation has been removed.  # noqa: E501
        pn_test = DHParameterNumbers(2, 7)
    except ValueError:
        # We get rid of the limitation through the cryptography v1.9 __init__.

        def DHParameterNumbers__init__hack(self, p, g, q=None):
            if (
                not isinstance(p, six.integer_types) or
                not isinstance(g, six.integer_types)
            ):
                raise TypeError("p and g must be integers")
            if q is not None and not isinstance(q, six.integer_types):
                raise TypeError("q must be integer or None")

            self._p = p
            self._g = g
            self._q = q

        DHParameterNumbers.__init__ = DHParameterNumbers__init__hack

    # End of hack.


_ffdh_groups = {}


class _FFDHParamsMetaclass(type):
    def __new__(cls, ffdh_name, bases, dct):
        the_class = super(_FFDHParamsMetaclass, cls).__new__(cls, ffdh_name,
                                                             bases, dct)
        if conf.crypto_valid and ffdh_name != "_FFDHParams":
            pn = DHParameterNumbers(the_class.m, the_class.g)
            params = pn.parameters(default_backend())
            _ffdh_groups[ffdh_name] = [params, the_class.mLen]
        return the_class


class _FFDHParams(six.with_metaclass(_FFDHParamsMetaclass)):
    pass


class modp768(_FFDHParams):
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
    8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
    302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
    A63A3620 FFFFFFFF FFFFFFFF""")
    mLen = 768


class modp1024(_FFDHParams):  # From RFC 4306
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
    8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
    302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
    A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
    49286651 ECE65381 FFFFFFFF FFFFFFFF""")
    mLen = 1024


class modp1536(_FFDHParams):  # From RFC 3526
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF""")
    mLen = 1536


class modp2048(_FFDHParams):  # From RFC 3526
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF""")
    mLen = 2048


class modp3072(_FFDHParams):  # From RFC 3526
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
    ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
    ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
    F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
    BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
    43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF""")
    mLen = 3072


class modp4096(_FFDHParams):  # From RFC 3526
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
    ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
    ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
    F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
    BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
    43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
    88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
    2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
    287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
    1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
    93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
    FFFFFFFF FFFFFFFF""")
    mLen = 4096


class modp6144(_FFDHParams):  # From RFC 3526
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
    8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
    302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
    A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
    49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
    FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
    180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
    3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
    04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
    B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
    1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
    BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
    E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
    99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
    04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
    233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
    D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
    36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406
    AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918
    DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151
    2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03
    F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F
    BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
    CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B
    B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632
    387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E
    6DCC4024 FFFFFFFF FFFFFFFF""")
    mLen = 6144


class modp8192(_FFDHParams):  # From RFC 3526
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
    ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
    ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
    F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
    BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
    43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
    88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
    2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
    287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
    1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
    93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
    36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD
    F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831
    179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B
    DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF
    5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6
    D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3
    23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
    CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328
    06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C
    DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE
    12BF2D5B 0B7474D6 E694F91E 6DBE1159 74A3926F 12FEE5E4
    38777CB6 A932DF8C D8BEC4D0 73B931BA 3BC832B6 8D9DD300
    741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C 5AE4F568
    3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9
    22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B
    4BCBC886 2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A
    062B3CF5 B3A278A6 6D2A13F8 3F44F82D DF310EE0 74AB6A36
    4597E899 A0255DC1 64F31CC5 0846851D F9AB4819 5DED7EA1
    B1D510BD 7EE74D73 FAF36BC3 1ECFA268 359046F4 EB879F92
    4009438B 481C6CD7 889A002E D5EE382B C9190DA6 FC026E47
    9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71
    60C980DD 98EDD3DF FFFFFFFF FFFFFFFF""")
    mLen = 8192


class ffdhe2048(_FFDHParams):  # From RFC 7919
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
    D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
    7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
    2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
    984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
    30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
    B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
    0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
    9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
    3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
    886B4238 61285C97 FFFFFFFF FFFFFFFF
    """)
    mLen = 2048


class ffdhe3072(_FFDHParams):  # From RFC 7919
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
    D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
    7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
    2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
    984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
    30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
    B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
    0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
    9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
    3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
    886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238
    61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C
    AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3
    64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D
    ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF
    3C1B20EE 3FD59D7C 25E41D2B 66C62E37 FFFFFFFF FFFFFFFF
    """)
    mLen = 3072


class ffdhe4096(_FFDHParams):  # From RFC 7919
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
    D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
    7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
    2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
    984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
    30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
    B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
    0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
    9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
    3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
    886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238
    61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C
    AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3
    64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D
    ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF
    3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB
    7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004
    87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832
    A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A
    1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF
    8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E655F6A
    FFFFFFFF FFFFFFFF
    """)
    mLen = 4096


class ffdhe6144(_FFDHParams):  # From RFC 7919
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
    D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
    7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
    2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
    984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
    30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
    B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
    0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
    9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
    3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
    886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238
    61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C
    AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3
    64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D
    ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF
    3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB
    7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004
    87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832
    A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A
    1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF
    8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E0DD902
    0BFD64B6 45036C7A 4E677D2C 38532A3A 23BA4442 CAF53EA6
    3BB45432 9B7624C8 917BDD64 B1C0FD4C B38E8C33 4C701C3A
    CDAD0657 FCCFEC71 9B1F5C3E 4E46041F 388147FB 4CFDB477
    A52471F7 A9A96910 B855322E DB6340D8 A00EF092 350511E3
    0ABEC1FF F9E3A26E 7FB29F8C 183023C3 587E38DA 0077D9B4
    763E4E4B 94B2BBC1 94C6651E 77CAF992 EEAAC023 2A281BF6
    B3A739C1 22611682 0AE8DB58 47A67CBE F9C9091B 462D538C
    D72B0374 6AE77F5E 62292C31 1562A846 505DC82D B854338A
    E49F5235 C95B9117 8CCF2DD5 CACEF403 EC9D1810 C6272B04
    5B3B71F9 DC6B80D6 3FDD4A8E 9ADB1E69 62A69526 D43161C1
    A41D570D 7938DAD4 A40E329C D0E40E65 FFFFFFFF FFFFFFFF
    """)
    mLen = 6144


class ffdhe8192(_FFDHParams):  # From RFC 7919
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
    D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
    7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
    2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
    984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
    30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
    B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
    0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
    9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
    3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
    886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238
    61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C
    AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3
    64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D
    ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF
    3C1B20EE 3FD59D7C 25E41D2B 669E1EF1 6E6F52C3 164DF4FB
    7930E9E4 E58857B6 AC7D5F42 D69F6D18 7763CF1D 55034004
    87F55BA5 7E31CC7A 7135C886 EFB4318A ED6A1E01 2D9E6832
    A907600A 918130C4 6DC778F9 71AD0038 092999A3 33CB8B7A
    1A1DB93D 7140003C 2A4ECEA9 F98D0ACC 0A8291CD CEC97DCF
    8EC9B55A 7F88A46B 4DB5A851 F44182E1 C68A007E 5E0DD902
    0BFD64B6 45036C7A 4E677D2C 38532A3A 23BA4442 CAF53EA6
    3BB45432 9B7624C8 917BDD64 B1C0FD4C B38E8C33 4C701C3A
    CDAD0657 FCCFEC71 9B1F5C3E 4E46041F 388147FB 4CFDB477
    A52471F7 A9A96910 B855322E DB6340D8 A00EF092 350511E3
    0ABEC1FF F9E3A26E 7FB29F8C 183023C3 587E38DA 0077D9B4
    763E4E4B 94B2BBC1 94C6651E 77CAF992 EEAAC023 2A281BF6
    B3A739C1 22611682 0AE8DB58 47A67CBE F9C9091B 462D538C
    D72B0374 6AE77F5E 62292C31 1562A846 505DC82D B854338A
    E49F5235 C95B9117 8CCF2DD5 CACEF403 EC9D1810 C6272B04
    5B3B71F9 DC6B80D6 3FDD4A8E 9ADB1E69 62A69526 D43161C1
    A41D570D 7938DAD4 A40E329C CFF46AAA 36AD004C F600C838
    1E425A31 D951AE64 FDB23FCE C9509D43 687FEB69 EDD1CC5E
    0B8CC3BD F64B10EF 86B63142 A3AB8829 555B2F74 7C932665
    CB2C0F1C C01BD702 29388839 D2AF05E4 54504AC7 8B758282
    2846C0BA 35C35F5C 59160CC0 46FD8251 541FC68C 9C86B022
    BB709987 6A460E74 51A8A931 09703FEE 1C217E6C 3826E52C
    51AA691E 0E423CFC 99E9E316 50C1217B 624816CD AD9A95F9
    D5B80194 88D9C0A0 A1FE3075 A577E231 83F81D4A 3F2FA457
    1EFC8CE0 BA8A4FE8 B6855DFE 72B0A66E DED2FBAB FBE58A30
    FAFABE1C 5D71A87E 2F741EF8 C1FE86FE A6BBFDE5 30677F0D
    97D11D49 F7A8443D 0822E506 A9F4614E 011E2A94 838FF88C
    D68C8BB7 C5C6424C FFFFFFFF FFFFFFFF
    """)
    mLen = 8192


_tls_named_ffdh_groups = {256: "ffdhe2048", 257: "ffdhe3072",
                          258: "ffdhe4096", 259: "ffdhe6144",
                          260: "ffdhe8192"}

_tls_named_curves = {1: "sect163k1", 2: "sect163r1", 3: "sect163r2",
                     4: "sect193r1", 5: "sect193r2", 6: "sect233k1",
                     7: "sect233r1", 8: "sect239k1", 9: "sect283k1",
                     10: "sect283r1", 11: "sect409k1", 12: "sect409r1",
                     13: "sect571k1", 14: "sect571r1", 15: "secp160k1",
                     16: "secp160r1", 17: "secp160r2", 18: "secp192k1",
                     19: "secp192r1", 20: "secp224k1", 21: "secp224r1",
                     22: "secp256k1", 23: "secp256r1", 24: "secp384r1",
                     25: "secp521r1", 26: "brainpoolP256r1",
                     27: "brainpoolP384r1", 28: "brainpoolP512r1",
                     29: "x25519", 30: "x448",
                     0xff01: "arbitrary_explicit_prime_curves",
                     0xff02: "arbitrary_explicit_char2_curves"}

_tls_named_groups = {}
_tls_named_groups.update(_tls_named_ffdh_groups)
_tls_named_groups.update(_tls_named_curves)


def _tls_named_groups_import(group, pubbytes):
    if group in _tls_named_ffdh_groups:
        params = _ffdh_groups[_tls_named_ffdh_groups[group]][0]
        pn = params.parameter_numbers()
        public_numbers = dh.DHPublicNumbers(pubbytes, pn)
        return public_numbers.public_key(default_backend())
    elif group in _tls_named_curves:
        if _tls_named_curves[group] in ["x25519", "x448"]:
            if conf.crypto_valid_advanced:
                if _tls_named_curves[group] == "x25519":
                    import_point = x25519.X25519PublicKey.from_public_bytes
                else:
                    import_point = x448.X448PublicKey.from_public_bytes
                return import_point(pubbytes)
        else:
            curve = ec._CURVE_TYPES[_tls_named_curves[group]]()
            try:  # cryptography >= 2.5
                return ec.EllipticCurvePublicKey.from_encoded_point(
                    curve,
                    pubbytes
                )
            except AttributeError:
                pub_num = ec.EllipticCurvePublicNumbers.from_encoded_point(
                    curve,
                    pubbytes
                ).public_numbers()
                return pub_num.public_key(default_backend())


def _tls_named_groups_pubbytes(privkey):
    if isinstance(privkey, dh.DHPrivateKey):
        pubkey = privkey.public_key()
        return pubkey.public_numbers().y
    elif isinstance(privkey, (x25519.X25519PrivateKey,
                              x448.X448PrivateKey)):
        pubkey = privkey.public_key()
        return pubkey.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
    else:
        pubkey = privkey.public_key()
        try:
            # cryptography >= 2.5
            return pubkey.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint
            )
        except TypeError:
            # older versions
            return pubkey.public_numbers().encode_point()


def _tls_named_groups_generate(group):
    if group in _tls_named_ffdh_groups:
        params = _ffdh_groups[_tls_named_ffdh_groups[group]][0]
        return params.generate_private_key()
    elif group in _tls_named_curves:
        group_name = _tls_named_curves[group]
        if group_name in ["x25519", "x448"]:
            if conf.crypto_valid_advanced:
                if group_name == "x25519":
                    return x25519.X25519PrivateKey.generate()
                else:
                    return x448.X448PrivateKey.generate()
            else:
                warning(
                    "Your cryptography version doesn't support " + group_name
                )
        else:
            curve = ec._CURVE_TYPES[_tls_named_curves[group]]()
            return ec.generate_private_key(curve, default_backend())

# Below lies ghost code since the shift from 'ecdsa' to 'cryptography' lib.
# Part of the code has been kept, but commented out, in case anyone would like
# to improve ECC support in 'cryptography' (namely for the compressed point
# format and additional curves).
#
# Recommended curve parameters from www.secg.org/SEC2-Ver-1.0.pdf
# and www.ecc-brainpool.org/download/Domain-parameters.pdf
#
#
# import math
#
# from scapy.utils import long_converter, binrepr
# from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp, pkcs_os2ip
#
#
# def encode_point(point, point_format=0):
#    """
#    Return a string representation of the Point p, according to point_format.
#    """
#    pLen = len(binrepr(point.curve().p()))
#    x = pkcs_i2osp(point.x(), math.ceil(pLen/8))
#    y = pkcs_i2osp(point.y(), math.ceil(pLen/8))
#    if point_format == 0:
#        frmt = b'\x04'
#    elif point_format == 1:
#        frmt = chr(2 + y%2)
#        y = ''
#    else:
#        raise Exception("No support for point_format %d" % point_format)
#    return frmt + x + y
#
#
# try:
#    import ecdsa
#    ecdsa_support = True
# except ImportError:
#    import logging
#    log_loading = logging.getLogger("scapy.loading")
#    log_loading.info("Can't import python ecdsa lib. No curves.")
#
#
# if ecdsa_support:
#
#    from ecdsa.ellipticcurve import CurveFp, Point
#    from ecdsa.curves import Curve
#    from ecdsa.numbertheory import square_root_mod_prime
#
#
#    def extract_coordinates(g, curve):
#        """
#        Return the coordinates x and y as integers,
#        regardless of the point format of string g.
#        Second expected parameter is a CurveFp.
#        """
#        p = curve.p()
#        point_format = g[0]
#        point = g[1:]
#        if point_format == b'\x04':
#            point_len = len(point)
#            if point_len % 2 != 0:
#                raise Exception("Point length is not even.")
#            x_bytes = point[:point_len>>1]
#            x = pkcs_os2ip(x_bytes) % p
#            y_bytes = point[point_len>>1:]
#            y = pkcs_os2ip(y_bytes) % p
#        elif point_format in [b'\x02', b'\x03']:
#            x_bytes = point
#            x = pkcs_os2ip(x_bytes) % p
#            # perform the y coordinate computation with self.tls_ec
#            y_square = (x*x*x + curve.a()*x + curve.b()) % p
#            y = square_root_mod_prime(y_square, p)
#            y_parity = ord(point_format) % 2    # \x02 means even, \x03 means odd  # noqa: E501
#            if y % 2 != y_parity:
#                y = -y % p
#        else:
#            raise Exception("Point starts with %s. This encoding "
#                            "is not recognized." % repr(point_format))
#        if not curve.contains_point(x, y):
#            raise Exception("The point we extracted does not belong on the curve!")  # noqa: E501
#        return x, y
#
#    def import_curve(p, a, b, g, r, name="dummyName", oid=(1, 3, 132, 0, 0xff)):  # noqa: E501
#        """
#        Create an ecdsa.curves.Curve from the usual parameters.
#        Arguments may be either octet strings or integers,
#        except g which we expect to be an octet string.
#        """
#        if isinstance(p, str):
#            p = pkcs_os2ip(p)
#        if isinstance(a, str):
#            a = pkcs_os2ip(a)
#        if isinstance(b, str):
#            b = pkcs_os2ip(b)
#        if isinstance(r, str):
#            r = pkcs_os2ip(r)
#        curve = CurveFp(p, a, b)
#        x, y = extract_coordinates(g, curve)
#        generator = Point(curve, x, y, r)
#        return Curve(name, curve, generator, oid)

# Named curves

# We always provide _a as a positive integer.

#    _p          = long_converter("""
#                  ffffffff ffffffff ffffffff fffffffe ffffac73""")
#    _a          = 0
#    _b          = 7
#    _Gx         = long_converter("""
#                  3b4c382c e37aa192 a4019e76 3036f4f5 dd4d7ebb""")
#    _Gy         = long_converter("""
#                  938cf935 318fdced 6bc28286 531733c3 f03c4fee""")
#    _r          = long_converter("""01
#                  00000000 00000000 0001b8fa 16dfab9a ca16b6b3""")
#    curve       = CurveFp(_p, _a, _b)
#    generator   = Point(curve, _Gx, _Gy, _r)
#    SECP160k1   = Curve("SECP160k1", curve, generator,
#                        (1, 3, 132, 0, 9), "secp160k1")

#    _p          = long_converter("""
#                  ffffffff ffffffff ffffffff ffffffff 7fffffff""")
#    _a          = -3 % _p
#    _b          = long_converter("""
#                  1c97befc 54bd7a8b 65acf89f 81d4d4ad c565fa45""")
#    _Gx         = long_converter("""
#                  4a96b568 8ef57328 46646989 68c38bb9 13cbfc82""")
#    _Gy         = long_converter("""
#                  23a62855 3168947d 59dcc912 04235137 7ac5fb32""")
#    _r          = long_converter("""01
#                  00000000 00000000 0001f4c8 f927aed3 ca752257""")
#    curve       = CurveFp(_p, _a, _b)
#    generator   = Point(curve, _Gx, _Gy, _r)
#    SECP160r1   = Curve("SECP160r1", curve, generator,
#                        (1, 3, 132, 0, 8), "secp160r1")

#    _p          = long_converter("""
#                  ffffffff ffffffff ffffffff fffffffe ffffac73""")
#    _a          = -3 % _p
#    _b          = long_converter("""
#                  b4e134d3 fb59eb8b ab572749 04664d5a f50388ba""")
#    _Gx         = long_converter("""
#                  52dcb034 293a117e 1f4ff11b 30f7199d 3144ce6d""")
#    _Gy         = long_converter("""
#                  feaffef2 e331f296 e071fa0d f9982cfe a7d43f2e""")
#    _r          = long_converter("""01
#                  00000000 00000000 0000351e e786a818 f3a1a16b""")
#    curve       = CurveFp(_p, _a, _b)
#    generator   = Point(curve, _Gx, _Gy, _r)
#    SECP160r2   = Curve("SECP160r2", curve, generator,
#                        (1, 3, 132, 0, 30), "secp160r2")

#    _p          = long_converter("""
#                  ffffffff ffffffff ffffffff ffffffff fffffffe ffffee37""")
#    _a          = 0
#    _b          = 3
#    _Gx         = long_converter("""
#                  db4ff10e c057e9ae 26b07d02 80b7f434 1da5d1b1 eae06c7d""")
#    _Gy         = long_converter("""
#                  9b2f2f6d 9c5628a7 844163d0 15be8634 4082aa88 d95e2f9d""")
#    _r          = long_converter("""
#                  ffffffff ffffffff fffffffe 26f2fc17 0f69466a 74defd8d""")
#    curve       = CurveFp(_p, _a, _b)
#    generator   = Point(curve, _Gx, _Gy, _r)
#    SECP192k1   = Curve("SECP192k1", curve, generator,
#                        (1, 3, 132, 0, 31), "secp192k1")

#    _p          = long_converter("""
#                  ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe
#                  ffffe56d""")
#    _a          = 0
#    _b          = 5
#    _Gx         = long_converter("""
#                  a1455b33 4df099df 30fc28a1 69a467e9 e47075a9 0f7e650e
#                  b6b7a45c""")
#    _Gy         = long_converter("""
#                  7e089fed 7fba3442 82cafbd6 f7e319f7 c0b0bd59 e2ca4bdb
#                  556d61a5""")
#    _r          = long_converter("""01
#                  00000000 00000000 00000000 0001dce8 d2ec6184 caf0a971
#                  769fb1f7""")
#    curve       = CurveFp(_p, _a, _b)
#    generator   = Point(curve, _Gx, _Gy, _r)
#    SECP224k1   = Curve("SECP224k1", curve, generator,
#                        (1, 3, 132, 0, 32), "secp224k1")

#    _p          = long_converter("""
#                  A9FB57DB A1EEA9BC 3E660A90 9D838D72 6E3BF623 D5262028
#                  2013481D 1F6E5377""")
#    _a          = long_converter("""
#                  7D5A0975 FC2C3057 EEF67530 417AFFE7 FB8055C1 26DC5C6C
#                  E94A4B44 F330B5D9""")
#    _b          = long_converter("""
#                  26DC5C6C E94A4B44 F330B5D9 BBD77CBF 95841629 5CF7E1CE
#                  6BCCDC18 FF8C07B6""")
#    _Gx         = long_converter("""
#                  8BD2AEB9 CB7E57CB 2C4B482F FC81B7AF B9DE27E1 E3BD23C2
#                  3A4453BD 9ACE3262""")
#    _Gy         = long_converter("""
#                  547EF835 C3DAC4FD 97F8461A 14611DC9 C2774513 2DED8E54
#                  5C1D54C7 2F046997""")
#    _r          = long_converter("""
#                  A9FB57DB A1EEA9BC 3E660A90 9D838D71 8C397AA3 B561A6F7
#                  901E0E82 974856A7""")
#    curve       = CurveFp(_p, _a, _b)
#    generator   = Point(curve, _Gx, _Gy, _r)
#    BRNP256r1   = Curve("BRNP256r1", curve, generator,
#                        (1, 3, 36, 3, 3, 2, 8, 1, 1, 7), "brainpoolP256r1")

#    _p          = long_converter("""
#                  8CB91E82 A3386D28 0F5D6F7E 50E641DF 152F7109 ED5456B4
#                  12B1DA19 7FB71123 ACD3A729 901D1A71 87470013 3107EC53""")
#    _a          = long_converter("""
#                  7BC382C6 3D8C150C 3C72080A CE05AFA0 C2BEA28E 4FB22787
#                  139165EF BA91F90F 8AA5814A 503AD4EB 04A8C7DD 22CE2826""")
#    _b          = long_converter("""
#                  04A8C7DD 22CE2826 8B39B554 16F0447C 2FB77DE1 07DCD2A6
#                  2E880EA5 3EEB62D5 7CB43902 95DBC994 3AB78696 FA504C11""")
#    _Gx         = long_converter("""
#                  1D1C64F0 68CF45FF A2A63A81 B7C13F6B 8847A3E7 7EF14FE3
#                  DB7FCAFE 0CBD10E8 E826E034 36D646AA EF87B2E2 47D4AF1E""")
#    _Gy         = long_converter("""
#                  8ABE1D75 20F9C2A4 5CB1EB8E 95CFD552 62B70B29 FEEC5864
#                  E19C054F F9912928 0E464621 77918111 42820341 263C5315""")
#    _r          = long_converter("""
#                  8CB91E82 A3386D28 0F5D6F7E 50E641DF 152F7109 ED5456B3
#                  1F166E6C AC0425A7 CF3AB6AF 6B7FC310 3B883202 E9046565""")
#    curve       = CurveFp(_p, _a, _b)
#    generator   = Point(curve, _Gx, _Gy, _r)
#    BRNP384r1   = Curve("BRNP384r1", curve, generator,
#                        (1, 3, 36, 3, 3, 2, 8, 1, 1, 11), "brainpoolP384r1")

#    _p          = long_converter("""
#                  AADD9DB8 DBE9C48B 3FD4E6AE 33C9FC07 CB308DB3 B3C9D20E
#                  D6639CCA 70330871 7D4D9B00 9BC66842 AECDA12A E6A380E6
#                  2881FF2F 2D82C685 28AA6056 583A48F3""")
#    _a          = long_converter("""
#                  7830A331 8B603B89 E2327145 AC234CC5 94CBDD8D 3DF91610
#                  A83441CA EA9863BC 2DED5D5A A8253AA1 0A2EF1C9 8B9AC8B5
#                  7F1117A7 2BF2C7B9 E7C1AC4D 77FC94CA""")
#    _b          = long_converter("""
#                  3DF91610 A83441CA EA9863BC 2DED5D5A A8253AA1 0A2EF1C9
#                  8B9AC8B5 7F1117A7 2BF2C7B9 E7C1AC4D 77FC94CA DC083E67
#                  984050B7 5EBAE5DD 2809BD63 8016F723""")
#    _Gx         = long_converter("""
#                  81AEE4BD D82ED964 5A21322E 9C4C6A93 85ED9F70 B5D916C1
#                  B43B62EE F4D0098E FF3B1F78 E2D0D48D 50D1687B 93B97D5F
#                  7C6D5047 406A5E68 8B352209 BCB9F822""")
#    _Gy         = long_converter("""
#                  7DDE385D 566332EC C0EABFA9 CF7822FD F209F700 24A57B1A
#                  A000C55B 881F8111 B2DCDE49 4A5F485E 5BCA4BD8 8A2763AE
#                  D1CA2B2F A8F05406 78CD1E0F 3AD80892""")
#    _r          = long_converter("""
#                  AADD9DB8 DBE9C48B 3FD4E6AE 33C9FC07 CB308DB3 B3C9D20E
#                  D6639CCA 70330870 553E5C41 4CA92619 41866119 7FAC1047
#                  1DB1D381 085DDADD B5879682 9CA90069""")
#    curve       = CurveFp(_p, _a, _b)
#    generator   = Point(curve, _Gx, _Gy, _r)
#    BRNP512r1   = Curve("BRNP512r1", curve, generator,
#                        (1, 3, 36, 3, 3, 2, 8, 1, 1, 13), "brainpoolP512r1")
