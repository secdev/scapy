## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) 2016 Pascal Delaunay, Maxence Tury
## This program is published under a GPLv2 license

"""
Implicit elliptic curves.
"""

# Recommended curve parameters from www.secg.org/SEC2-Ver-1.0.pdf
# and www.ecc-brainpool.org/download/Domain-parameters.pdf
# Note that this module will overwrite curves from python-ecdsa.

import math
from ecdsa.ellipticcurve import CurveFp, Point
from ecdsa.curves import Curve
from ecdsa.numbertheory import square_root_mod_prime

from scapy.utils import long_converter, binrepr
from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp, pkcs_os2ip


##############################################################
# Some helpers
##############################################################

def encode_point(point, point_format=0):
    """
    Return a string representation of the Point p, according to point_format.
    """
    pLen = len(binrepr(point.curve().p()))
    x = pkcs_i2osp(point.x(), math.ceil(pLen/8))
    y = pkcs_i2osp(point.y(), math.ceil(pLen/8))
    if point_format == 0:
        frmt = '\x04'
    elif point_format == 1:
        frmt = chr(2 + y%2)
        y = ''
    else:
        raise Exception("No support for point_format %d" % point_format)
    return frmt + x + y

def extract_coordinates(g, curve):
    """
    Return the coordinates x and y as integers,
    regardless of the point format of string g.
    Second expected parameter is a CurveFp.
    """
    p = curve.p()
    point_format = g[0]
    point = g[1:]
    if point_format == '\x04':
        point_len = len(point)
        if point_len % 2 != 0:
            raise Exception("Point length is not even.")
        x_bytes = point[:point_len>>1]
        x = pkcs_os2ip(x_bytes) % p
        y_bytes = point[point_len>>1:]
        y = pkcs_os2ip(y_bytes) % p
    elif point_format in ['\x02', '\x03']:
        x_bytes = point
        x = pkcs_os2ip(x_bytes) % p
        # perform the y coordinate computation with self.tls_ec
        y_square = (x*x*x + curve.a()*x + curve.b()) % p
        y = square_root_mod_prime(y_square, p)
        y_parity = ord(point_format) % 2    # \x02 means even, \x03 means odd
        if y % 2 != y_parity:
            y = -y % p
    else:
        raise Exception("Point starts with %s. This encoding "
                        "is not recognized." % repr(point_format))
    if not curve.contains_point(x, y):
        raise Exception("The point we extracted does not belong on the curve!")
    return x, y

def import_curve(p, a, b, g, r, name="dummyName", oid=(1, 3, 132, 0, 0xff)):
    """
    Create an ecdsa.curves.Curve from the usual parameters.
    Arguments may be either octet strings or integers,
    except g which we expect to be an octet string.
    """
    if isinstance(p, str):
        p = pkcs_os2ip(p)
    if isinstance(a, str):
        a = pkcs_os2ip(a)
    if isinstance(b, str):
        b = pkcs_os2ip(b)
    if isinstance(r, str):
        r = pkcs_os2ip(r)
    curve = CurveFp(p, a, b)
    x, y = extract_coordinates(g, curve)
    generator = Point(curve, x, y, r)
    return Curve(name, curve, generator, oid)


##############################################################
# Named curves
##############################################################

# We always provide _a as a positive integer.

_p          = long_converter("""
              ffffffff ffffffff ffffffff fffffffe ffffac73""")
_a          = 0
_b          = 7
_Gx         = long_converter("""
              3b4c382c e37aa192 a4019e76 3036f4f5 dd4d7ebb""")
_Gy         = long_converter("""
              938cf935 318fdced 6bc28286 531733c3 f03c4fee""")
_r          = long_converter("""01
              00000000 00000000 0001b8fa 16dfab9a ca16b6b3""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
SECP160k1   = Curve("SECP160k1", curve, generator,
                    (1, 3, 132, 0, 9), "secp160k1")

_p          = long_converter("""
              ffffffff ffffffff ffffffff ffffffff 7fffffff""")
_a          = -3 % _p
_b          = long_converter("""
              1c97befc 54bd7a8b 65acf89f 81d4d4ad c565fa45""")
_Gx         = long_converter("""
              4a96b568 8ef57328 46646989 68c38bb9 13cbfc82""")
_Gy         = long_converter("""
              23a62855 3168947d 59dcc912 04235137 7ac5fb32""")
_r          = long_converter("""01
              00000000 00000000 0001f4c8 f927aed3 ca752257""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
SECP160r1   = Curve("SECP160r1", curve, generator,
                    (1, 3, 132, 0, 8), "secp160r1")

_p          = long_converter("""
              ffffffff ffffffff ffffffff fffffffe ffffac73""")
_a          = -3 % _p
_b          = long_converter("""
              b4e134d3 fb59eb8b ab572749 04664d5a f50388ba""")
_Gx         = long_converter("""
              52dcb034 293a117e 1f4ff11b 30f7199d 3144ce6d""")
_Gy         = long_converter("""
              feaffef2 e331f296 e071fa0d f9982cfe a7d43f2e""")
_r          = long_converter("""01
              00000000 00000000 0000351e e786a818 f3a1a16b""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
SECP160r2   = Curve("SECP160r2", curve, generator,
                    (1, 3, 132, 0, 30), "secp160r2")

_p          = long_converter("""
              ffffffff ffffffff ffffffff ffffffff fffffffe ffffee37""")
_a          = 0
_b          = 3
_Gx         = long_converter("""
              db4ff10e c057e9ae 26b07d02 80b7f434 1da5d1b1 eae06c7d""")
_Gy         = long_converter("""
              9b2f2f6d 9c5628a7 844163d0 15be8634 4082aa88 d95e2f9d""")
_r          = long_converter("""
              ffffffff ffffffff fffffffe 26f2fc17 0f69466a 74defd8d""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
SECP192k1   = Curve("SECP192k1", curve, generator,
                    (1, 3, 132, 0, 31), "secp192k1")

_p          = long_converter("""
              ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff""")
_a          = -3 % _p
_b          = long_converter("""
              64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1""")
_Gx         = long_converter("""
              188da80e b03090f6 7cbf20eb 43a18800 f4ff0afd 82ff1012""")
_Gy         = long_converter("""
              07192b95 ffc8da78 631011ed 6b24cdd5 73f977a1 1e794811""")
_r          = long_converter("""
              ffffffff ffffffff ffffffff 99def836 146bc9b1 b4d22831""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
SECP192r1   = Curve("SECP192r1", curve, generator,
                    (1, 2, 840, 10045, 3, 1, 1), "prime192v1")

_p          = long_converter("""
              ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe
              ffffe56d""")
_a          = 0
_b          = 5
_Gx         = long_converter("""
              a1455b33 4df099df 30fc28a1 69a467e9 e47075a9 0f7e650e
              b6b7a45c""")
_Gy         = long_converter("""
              7e089fed 7fba3442 82cafbd6 f7e319f7 c0b0bd59 e2ca4bdb
              556d61a5""")
_r          = long_converter("""01
              00000000 00000000 00000000 0001dce8 d2ec6184 caf0a971
              769fb1f7""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
SECP224k1   = Curve("SECP224k1", curve, generator,
                    (1, 3, 132, 0, 32), "secp224k1")

_p          = long_converter("""
              ffffffff ffffffff ffffffff ffffffff 00000000 00000000
              00000001""")
_a          = -3 % _p
_b          = long_converter("""
              b4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943
              2355ffb4""")
_Gx         = long_converter("""
              b70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6
              115c1d21""")
_Gy         = long_converter("""
              bd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199
              85007e34""")
_r          = long_converter("""
              ffffffff ffffffff ffffffff ffff16a2 e0b8f03e 13dd2945
              5c5c2a3d""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
SECP224r1   = Curve("SECP224r1", curve, generator,
                    (1, 3, 132, 0, 33), "secp224r1")

# (already defined as SECP256k1 by python-ecdsa)
_p          = long_converter("""
              ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff
              fffffffe fffffc2f""")
_a          = 0
_b          = 7
_Gx         = long_converter("""
              79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9
              59f2815b 16f81798""")
_Gy         = long_converter("""
              483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419
              9c47d08f fb10d4b8""")
_r          = long_converter("""
              ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b
              bfd25e8c d0364141""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
SECP256k1   = Curve("SECP256k1", curve, generator,
                    (1, 3, 132, 0, 10), "secp256k1")

_p          = long_converter("""
              ffffffff 00000001 00000000 00000000 00000000 ffffffff
              ffffffff ffffffff""")
_a          = -3 % _p
_b          = long_converter("""
              5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6
              3bce3c3e 27d2604b""")
_Gx         = long_converter("""
              6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0
              f4a13945 d898c296""")
_Gy         = long_converter("""
              4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece
              cbb64068 37bf51f5""")
_r          = long_converter("""
              ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84
              f3b9cac2 fc632551""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
SECP256r1   = Curve("SECP256r1", curve, generator,
                    (1, 2, 840, 10045, 3, 1, 7), "prime256v1")

_p          = long_converter("""
              ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff
              ffffffff fffffffe ffffffff 00000000 00000000 ffffffff""")
_a          = -3 % _p
_b          = long_converter("""
              b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112
              0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef""")
_Gx         = long_converter("""
              aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98
              59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7""")
_Gy         = long_converter("""
              3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c
              e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f""")
_r          = long_converter("""
              ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff
              c7634d81 f4372ddf 581a0db2 48b0a77a ecec196a ccc52973""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
SECP384r1   = Curve("SECP384r1", curve, generator,
                    (1, 3, 132, 0, 34), "secp384r1")

_p          = long_converter("""
                  01ff ffffffff ffffffff ffffffff ffffffff ffffffff
              ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff
              ffffffff ffffffff ffffffff ffffffff ffffffff""")
_a          = -3 % _p
_b          = long_converter("""
                  0051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b
              99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd
              3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00""")
_Gx         = long_converter("""
                  00c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139
              053fb521 f828af60 6b4d3dba a14b5e77 efe75928 fe1dc127
              a2ffa8de 3348b3c1 856a429b f97e7e31 c2e5bd66""")
_Gy         = long_converter("""
                  0118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 98f54449
              579b4468 17afbd17 273e662c 97ee7299 5ef42640 c550b901
              3fad0761 353c7086 a272c240 88be9476 9fd16650""")
_r          = long_converter("""
                  01ff ffffffff ffffffff ffffffff ffffffff ffffffff
              ffffffff ffffffff fffffffa 51868783 bf2f966b 7fcc0148
              f709a5d0 3bb5c9b8 899c47ae bb6fb71e 91386409""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
SECP521r1   = Curve("SECP521r1", curve, generator,
                    (1, 3, 132, 0, 35), "secp521r1")

_p          = long_converter("""
              A9FB57DB A1EEA9BC 3E660A90 9D838D72 6E3BF623 D5262028
              2013481D 1F6E5377""")
_a          = long_converter("""
              7D5A0975 FC2C3057 EEF67530 417AFFE7 FB8055C1 26DC5C6C
              E94A4B44 F330B5D9""")
_b          = long_converter("""
              26DC5C6C E94A4B44 F330B5D9 BBD77CBF 95841629 5CF7E1CE
              6BCCDC18 FF8C07B6""")
_Gx         = long_converter("""
              8BD2AEB9 CB7E57CB 2C4B482F FC81B7AF B9DE27E1 E3BD23C2
              3A4453BD 9ACE3262""")
_Gy         = long_converter("""
              547EF835 C3DAC4FD 97F8461A 14611DC9 C2774513 2DED8E54
              5C1D54C7 2F046997""")
_r          = long_converter("""
              A9FB57DB A1EEA9BC 3E660A90 9D838D71 8C397AA3 B561A6F7
              901E0E82 974856A7""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
BRNP256r1   = Curve("BRNP256r1", curve, generator,
                    (1, 3, 36, 3, 3, 2, 8, 1, 1, 7), "brainpoolP256r1")

_p          = long_converter("""
              8CB91E82 A3386D28 0F5D6F7E 50E641DF 152F7109 ED5456B4
              12B1DA19 7FB71123 ACD3A729 901D1A71 87470013 3107EC53""")
_a          = long_converter("""
              7BC382C6 3D8C150C 3C72080A CE05AFA0 C2BEA28E 4FB22787
              139165EF BA91F90F 8AA5814A 503AD4EB 04A8C7DD 22CE2826""")
_b          = long_converter("""
              04A8C7DD 22CE2826 8B39B554 16F0447C 2FB77DE1 07DCD2A6
              2E880EA5 3EEB62D5 7CB43902 95DBC994 3AB78696 FA504C11""")
_Gx         = long_converter("""
              1D1C64F0 68CF45FF A2A63A81 B7C13F6B 8847A3E7 7EF14FE3
              DB7FCAFE 0CBD10E8 E826E034 36D646AA EF87B2E2 47D4AF1E""")
_Gy         = long_converter("""
              8ABE1D75 20F9C2A4 5CB1EB8E 95CFD552 62B70B29 FEEC5864
              E19C054F F9912928 0E464621 77918111 42820341 263C5315""")
_r          = long_converter("""
              8CB91E82 A3386D28 0F5D6F7E 50E641DF 152F7109 ED5456B3
              1F166E6C AC0425A7 CF3AB6AF 6B7FC310 3B883202 E9046565""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
BRNP384r1   = Curve("BRNP384r1", curve, generator,
                    (1, 3, 36, 3, 3, 2, 8, 1, 1, 11), "brainpoolP384r1")

_p          = long_converter("""
              AADD9DB8 DBE9C48B 3FD4E6AE 33C9FC07 CB308DB3 B3C9D20E
              D6639CCA 70330871 7D4D9B00 9BC66842 AECDA12A E6A380E6
              2881FF2F 2D82C685 28AA6056 583A48F3""")
_a          = long_converter("""
              7830A331 8B603B89 E2327145 AC234CC5 94CBDD8D 3DF91610
              A83441CA EA9863BC 2DED5D5A A8253AA1 0A2EF1C9 8B9AC8B5
              7F1117A7 2BF2C7B9 E7C1AC4D 77FC94CA""")
_b          = long_converter("""
              3DF91610 A83441CA EA9863BC 2DED5D5A A8253AA1 0A2EF1C9
              8B9AC8B5 7F1117A7 2BF2C7B9 E7C1AC4D 77FC94CA DC083E67
              984050B7 5EBAE5DD 2809BD63 8016F723""")
_Gx         = long_converter("""
              81AEE4BD D82ED964 5A21322E 9C4C6A93 85ED9F70 B5D916C1
              B43B62EE F4D0098E FF3B1F78 E2D0D48D 50D1687B 93B97D5F
              7C6D5047 406A5E68 8B352209 BCB9F822""")
_Gy         = long_converter("""
              7DDE385D 566332EC C0EABFA9 CF7822FD F209F700 24A57B1A
              A000C55B 881F8111 B2DCDE49 4A5F485E 5BCA4BD8 8A2763AE
              D1CA2B2F A8F05406 78CD1E0F 3AD80892""")
_r          = long_converter("""
              AADD9DB8 DBE9C48B 3FD4E6AE 33C9FC07 CB308DB3 B3C9D20E
              D6639CCA 70330870 553E5C41 4CA92619 41866119 7FAC1047
              1DB1D381 085DDADD B5879682 9CA90069""")
curve       = CurveFp(_p, _a, _b)
generator   = Point(curve, _Gx, _Gy, _r)
BRNP512r1   = Curve("BRNP512r1", curve, generator,
                    (1, 3, 36, 3, 3, 2, 8, 1, 1, 13), "brainpoolP512r1")

# we use IANA identifiers below
named_curves = { 15: SECP160k1,
                 16: SECP160r1,
                 17: SECP160r2,
                 18: SECP192k1,
                 19: SECP192r1,
                 20: SECP224k1,
                 21: SECP224r1,
                 22: SECP256k1,
                 23: SECP256r1,
                 24: SECP384r1,
                 25: SECP521r1,
                 26: BRNP256r1,
                 27: BRNP384r1,
                 28: BRNP512r1
               }

for cid, c in named_curves.iteritems():
    c.curve_id = cid

# replace/fill previous named curves
import ecdsa.curves
ecdsa.curves.curves = named_curves.values()

