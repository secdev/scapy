## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
This is a register for DH groups from RFC 3526 and RFC 4306.
XXX These groups (and the ones from RFC 7919) should be registered to
the cryptography library. And this file should eventually be removed.
"""
from __future__ import absolute_import

from scapy.config import conf
if conf.crypto_valid:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import dh
else:
    default_backend = dh = None

from scapy.utils import long_converter
import scapy.modules.six as six


class modp768: # From RFC 4306
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
    8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
    302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
    A63A3620 FFFFFFFF FFFFFFFF""")
    mLen = 768

class modp1024: # From RFC 4306
    g = 0x02
    m = long_converter("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
    8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
    302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
    A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
    49286651 ECE65381 FFFFFFFF FFFFFFFF""")
    mLen  = 1024

class modp1536: # From RFC 3526
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
    mLen  = 1536

class modp2048: # From RFC 3526
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
    mLen  = 2048

class modp3072: # From RFC 3526
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
    mLen  = 3072

class modp4096: # From RFC 3526
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
    mLen  = 4096

class modp6144: # From RFC 3526
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

class modp8192: # From RFC 3526
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

_ffdh_raw_params = { 'modp768' : modp768,
                     'modp1024': modp1024,
                     'modp1536': modp1536,
                     'modp2048': modp2048,
                     'modp3072': modp3072,
                     'modp4096': modp4096,
                     'modp6144': modp6144,
                     'modp8192': modp8192  }

FFDH_GROUPS = {}
if dh and default_backend:
    for name, group in six.iteritems(_ffdh_raw_params):
        pn = dh.DHParameterNumbers(group.m, group.g)
        params = pn.parameters(default_backend())
        FFDH_GROUPS[name] = [params, group.mLen]


#from scapy.layers.tls.crypto.pkcs1 import pkcs_os2ip, pkcs_i2osp
#
#
#class FFDHParams(object):
#    """
#    Finite-Field Diffie-Hellman parameters.
#    self.priv is an integer. Its value may remain unknown.
#    self.pub, self.other_pub, and finally self.secret, are also integers.
#    Default group parameters relate to the 2048-bit group from RFC 3526.
#    """
#    def __init__(self, g=ffdh_params[2048].g,
#                       m=ffdh_params[2048].m,
#                       mLen=ffdh_params[2048].mLen):
#        """
#           g: group (2, 5, ...). Can be provided as a string or long.
#           m: prime modulus. Can be provided as a string or long.
#        mLen: prime modulus length in bits.
#        """
#        if type(g) is str:
#            g = pkcs_os2ip(g)
#        if type(m) is str:
#            m = pkcs_os2ip(m)
#
#        self.g = long(g)
#        self.m = long(m)
#        self.mLen = mLen
#
#        self.priv       = None
#        self.pub        = None
#        self.other_pub  = None
#        self.secret     = None
#
#    def gen_public_params(self):
#        """
#        Generate FFDH public parameter, by choosing a random private
#        value in ] 0, p-1 [ and then exponentiating the generator of
#        the group with the private value. The public parameter is
#        returned as an octet string. The private parameter is internally
#        available for further secret generation (using .gen_secret()).
#
#        Note that 'secret' and 'other_pub' attribute of the instance
#        are reset by the call.
#        """
#        self.other_pub  = None
#        self.secret     = None
#
#        # Private key generation : 0 < x < p-1
#        x = random.randint(1, self.m-2)
#        self.priv = x
#
#        # Exponentiation
#        y = pow(self.g, self.priv, self.m)
#        self.pub = y
#
#        # Integer-to-octet-string conversion
#        y = pkcs_i2osp(y, self.mLen/8)
#
#        return y
#
#    def gen_secret(self, other_pub):
#        """
#        Given the peer's public value 'other_pub' provided as an octet string,
#        the shared secret is computed by exponentiating the value using
#        internally stored private value (self.priv, generated during
#        public_parameter generation using .gen_public_params()).
#
#        Computed secret is returned as a bitstring and stored internally.
#
#        No specific check is done on 'other_pub' before exponentiation.
#        """
#        if type(other_pub) is str:
#            other_pub = pkcs_os2ip(other_pub)
#
#        # Octet-string-to-integer conversion
#        self.other_pub = other_pub
#
#        # Exponentiation
#        z = pow(other_pub, self.priv, self.m)
#
#        # Integer-to-octet-string conversion
#        z = pkcs_i2osp(z, self.mLen/8)
#        self.secret = z
#
#        return z
#
#    def check_params(self):
#        #XXX Do me, maybe
#        pass

