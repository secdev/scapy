## This file is part of Scapy
## Copyright (C) 2016 Pascal Delaunay, Maxence Tury
## This program is published under a GPLv2 license

"""
Primitive Elliptic Curve Diffie-Hellman module.
"""

import random

from scapy.layers.tls.crypto.curves import (Point,
                                            named_curves,
                                            import_curve,
                                            encode_point,
                                            extract_coordinates)
from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp


class ECParams(object):
    def __init__(self, curve_type):
        """
        RFC 3279: ec_type = 1 for prime-fields
                          = 2 for char-two-fields (no real support for now)
        As to self.curve, it stores an ecdsa.curves.Curve.
        """
        self.ec_type = None
        self.curve = None

    def set_named_curve(self, curve_tls_id):
        """
        Identify and store the named curve we're working with.
        We always set self.ec_type to 1 because, for now at least,
        there are no char2 curves among the named_curves.
        """
        if curve_tls_id not in named_curves:
            raise Exception("Unsupported named curve id %d" % curve_tls_id)
        self.curve = named_curves[curve_tls_id]
        self.ec_type = 1

    def set_explicit_char2_curve(self, basetype, base, a, b, g, r):
        self.ec_type = 2
        raise Exception("No char2 support for now")

    def set_explicit_prime_curve(self, p, a, b, g, r):
        """
        Create and store the explicit curve we're working with.
        """
        self.ec_type = 1
        self.curve = import_curve(p, a, b, g, r)


class ECDHParams(object):
    """
    Elliptic Curve Diffie-Hellman parameters.
    Holds an instance of ECParams and some attributes of the DH algorithm.
    These are used in ServerECDH*Params for the TLS key exchange.

    self.priv is an integer. Its value may remain unknown.

    self.pub and self.other_pub values (the public value we generated and the
    one we received) are encoded as octet strings according to point_format.

    self.secret is the shared secret, also encoded as an octet string.

    Default ec_parameters relate to the SECP256r1 curve.
    """
    def __init__(self, ec_parameters=None, point_format=0):
        """
        RFC 4492: point_format = 0 for uncompressed
                               = 1 for compressed_prime
                               = 2 for compressed_char2
        """
        if ec_parameters is None:
            ec_parameters = ECParams(1)
            ec_parameters.set_named_curve(23)
        self.ec_parameters = ec_parameters

        if point_format not in [0, 1]:
            if point_format == 2:
                raise Exception("No support for ansiX962_compressed_char2")
            else:
                raise Exception("Unknown point format")
        self.point_format   = point_format

        self.priv           = None
        self.pub            = None
        self.other_pub      = None
        self.secret         = None

    def gen_public_params(self):
        """
        Generate ECDH public parameter, by choosing a random private value
        in ] 0, self.ec_parameters.generator.order() [ and then multiplying
        the generator of the group self.ec_parameters.base with the
        private value. The public point is returned as a bitstring.
        The private parameter is internally available for further
        secret generation (using .gen_secret()).

        Note that 'secret', 'secret_point', 'other_pub' and 'other_pub_point'
        attributes of the instance are reset by the call.
        """
        self.other_pub      = None
        self.secret         = None

        params = self.ec_parameters
        if params.ec_type == 1:
            # Variables, for readability
            order   = params.curve.order
            base    = params.curve.generator

            # Ephemeral private key generation : self.priv in [1..order-1]
            self.priv = random.randint(1, order-1)

            # Scalar multiplication of priv and base point in pub_point
            pub_point = self.priv * base

            # Encode the public key to be sent according to our point_format
            self.pub = encode_point(pub_point, point_format=self.point_format)
        else:
            raise Exception("No support for ec_type %d" % params.ec_type)

        return self.pub

    def gen_secret(self, other_pub):
        """
        Given the peer's public point 'other_pub' as an octet string,
        the shared secret is computed by multiplying the value with
        self.priv which was generated with .gen_public_params()
        """
        if type(other_pub) is not str:
            blen = self.ec_parameters.curve.baselen
            if self.point_format == 1:
                other_pub = pkcs_i2osp(other_pub, blen)
            else:
                other_pub = pkcs_i2osp(other_pub, 2*blen+1)

        self.other_pub = other_pub

        z = ""
        params = self.ec_parameters
        if params.ec_type == 1:
            # Get underlying variables for readability
            ec = params.curve
            curveFp = ec.curve
            order = ec.order

            x, y = extract_coordinates(self.other_pub, curveFp)

            # Construct the other_pub_point with integers (mod p) x and y
            other_pub_point = Point(curveFp, x, y, order)

            # Scalar multiplication with ephemeral private key
            secret_point = self.priv * other_pub_point

            # Shared secret is x-coordinate of secret_point as an octet string
            secret_long = secret_point.x()

            # Note that this string never depends on point_format
            z = pkcs_i2osp(secret_long, ec.baselen)
            self.secret = z
        else:
            raise Exception("No support for ec_type %d" % params.ec_type)

        return z

    def check_params(self):
        #XXX Do me, maybe
        pass

