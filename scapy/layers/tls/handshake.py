## This file is part of Scapy
## Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
##                     2015, 2016 Maxence Tury
## This program is published under a GPLv2 license

"""
TLS handshake fields & logic.

This module covers the handshake TLS subprotocol, except for the key exchange
mechanisms which are addressed with keyexchange.py.
"""

import math

from scapy.error import warning
from scapy.fields import *
from scapy.packet import Packet, Raw, Padding
from scapy.utils import repr_hex
from scapy.layers.x509 import X509_Extensions, OCSP_Response
from scapy.layers.tls.cert import Cert, PrivKey, PubKey
from scapy.layers.tls.basefields import _tls_version, _TLSVersionField
from scapy.layers.tls.keyexchange import (_tls_named_curves, _tls_hash_sig,
                                          _TLSSignature, _TLSServerParamsField,
                                          _TLSSignatureField, ServerRSAParams,
                                          SigAndHashAlgsField,
                                          SigAndHashAlgsLenField)
from scapy.layers.tls.session import (_GenericTLSSessionInheritance,
                                      writeConnState,
                                      readConnState)
from scapy.layers.tls.crypto.compression import (_tls_compression_algs,
                                                 _tls_compression_algs_cls,
                                                 _GenericComp,
                                                 _GenericCompMetaclass)
from scapy.layers.tls.crypto.suites import (_tls_cipher_suites,
                                            _tls_cipher_suites_cls,
                                            _GenericCipherSuite,
                                            _GenericCipherSuiteMetaclass,
                                            TLS_DHE_RSA_WITH_AES_128_CBC_SHA)


###############################################################################
### Generic TLS Handshake message                                           ###
###############################################################################

_tls_handshake_type = { 0: "hello_request",         1: "client_hello",
                        2: "server_hello",          3: "hello_verify_request",
                        4: "session_ticket",        11: "certificate",
                        12: "server_key_exchange",  13: "certificate_request",
                        14: "server_hello_done",    15: "certificate_verify",
                        16: "client_key_exchange",  20: "finished",
                        21: "certificate_url",      22: "certificate_status",
                        23: "supplemental_data" }


class _TLSHandshake(_GenericTLSSessionInheritance):
    """
    Inherited by other Handshake classes to get post_build().
    Also used as a fallback for unknown TLS Handshake packets.
    """
    name = "TLS Handshake Generic message"
    fields_desc = [ ByteEnumField("msgtype", None, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    StrLenField("msg", "",
                                length_from=lambda pkt: pkt.msglen) ]

    def post_build(self, p, pay):
        l = len(p)
        if self.msglen is None:
            l2 = l - 4
            p = struct.pack("!I", (ord(p[0]) << 24) | l2) + p[4:]
        return p + pay

    def guess_payload_class(self, p):
        return Padding

    def tls_session_update(self, msg_str):
        """
        Covers both post_build- and post_dissection- context updates.
        """
        self.tls_session.handshake_messages.append(msg_str)
        self.tls_session.handshake_messages_parsed.append(self)


###############################################################################
### HelloRequest                                                            ###
###############################################################################

class TLSHelloRequest(_TLSHandshake):
    name = "TLS Handshake - Hello Request"
    fields_desc = [ ByteEnumField("msgtype", 0, _tls_handshake_type),
                    ThreeBytesField("msglen", None) ]

    def tls_session_update(self, msg_str):
        """
        Message should not be added to the list of handshake messages
        that will be hashed in the finished and certificate verify messages.
        """
        return


###############################################################################
### ClientHello fields                                                      ###
###############################################################################

class _GMTUnixTimeField(IntField):
    """
    Piggybacked from scapy6 UTCTimeField
    "The current time and date in standard UNIX 32-bit format (seconds since
     the midnight starting Jan 1, 1970, GMT, ignoring leap seconds)."
    """
    epoch = (1970, 1, 1, 0, 0, 0, 3, 1, 0)

    def i2repr(self, pkt, x):
        x = self.i2h(pkt, x)
        from time import gmtime, strftime, mktime
        delta = mktime(gmtime(0)) - mktime(self.epoch)
        x = x-delta
        t = strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime(x))
        return "%s (%d)" % (t, x)

    def i2h(self, pkt, x):
        if x is not None:
            return x
        return 0

class _TLSRandomBytesField(StrFixedLenField):
    def i2repr(self, pkt, x):
        if x is None:
            return repr(x)
        return repr_hex(self.i2h(pkt,x))


class _SessionIDField(StrLenField):
    """
    opaque SessionID<0..32>; section 7.4.1.2 of RFC 4346
    """
    pass


class _CipherSuitesField(StrLenField):
    __slots__ = ["itemfmt", "itemsize", "i2s", "s2i"]
    islist = 1
    def __init__(self, name, default, dico, length_from=None, itemfmt="!H"):
        StrLenField.__init__(self, name, default, length_from=length_from)
        self.itemfmt = itemfmt
        self.itemsize = struct.calcsize(itemfmt)
        i2s = self.i2s = {}
        s2i = self.s2i = {}
        keys = dico.keys()
        for k in keys:
            i2s[k] = dico[k]
            s2i[dico[k]] = k

    def any2i_one(self, pkt, x):
        if (isinstance(x, _GenericCipherSuite) or
            isinstance(x, _GenericCipherSuiteMetaclass)):
            x = x.val
        if type(x) is str:
            x = self.s2i[x]
        return x

    def i2repr_one(self, pkt, x):
        fmt = "0x%%0%dx" % self.itemsize
        return self.i2s.get(x, fmt % x)

    def any2i(self, pkt, x):
        if type(x) is not list:
            x = [x]
        return map(lambda z,pkt=pkt:self.any2i_one(pkt,z), x)

    def i2repr(self, pkt, x):
        if x is None:
            return "None"
        l = map(lambda z,pkt=pkt:self.i2repr_one(pkt,z), x)
        if len(l) == 1:
            l = l[0]
        else:
            l = "[%s]" % ", ".join(l)
        return l

    def i2m(self, pkt, val):
        if val is None:
            val = []
        return "".join(map(lambda x: struct.pack(self.itemfmt, x), val))

    def m2i(self, pkt, m):
        res = []
        itemlen = struct.calcsize(self.itemfmt)
        while m:
            res.append(struct.unpack(self.itemfmt, m[:itemlen])[0])
            m = m[itemlen:]
        return res

    def i2len(self, pkt, i):
        return len(i)*self.itemsize


class _CompressionMethodsField(_CipherSuitesField):

    def any2i_one(self, pkt, x):
        if (isinstance(x, _GenericComp) or
            isinstance(x, _GenericCompMetaclass)):
            x = x.val
        if type(x) is str:
            x = self.s2i[x]
        return x


###############################################################################
### ClientHello/ServerHello extensions                                      ###
###############################################################################

# We provide these extensions mostly for packet manipulation purposes.
# For now, most of them are not considered by our automaton.

_tls_ext = {  0: "server_name",             # RFC 4366
              1: "max_fragment_length",     # RFC 4366
              2: "client_certificate_url",  # RFC 4366
              3: "trusted_ca_keys",         # RFC 4366
              4: "truncated_hmac",          # RFC 4366
              5: "status_request",          # RFC 4366
              6: "user_mapping",            # RFC 4681
              7: "client_authz",            # RFC 5878
              8: "server_authz",            # RFC 5878
              9: "cert_type",               # RFC 6091
             10: "elliptic_curves",         # RFC 4492
             11: "ec_point_formats",        # RFC 4492
             13: "signature_algorithms",    # RFC 5246
             0x0f: "heartbeat",             # RFC 6520
             0x10: "alpn",                  # RFC 7301
             0x15: "padding",               # RFC 7685
             0x23: "session_ticket",        # RFC 5077
             0x3374: "next_protocol_negotiation",
                                            # RFC-draft-agl-tls-nextprotoneg-03
             0xff01: "renegotiation_info"   # RFC 5746
             }


class TLS_Ext_Unknown(_GenericTLSSessionInheritance):
    name = "TLS Extension - Scapy Unknown"
    fields_desc = [ShortEnumField("type", None, _tls_ext),
                   FieldLenField("len", None, fmt="!H", length_of="val"),
                   StrLenField("val", "",
                               length_from=lambda pkt: pkt.len) ]

    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 4
            p = p[:2] + struct.pack("!H", l) + p[4:]
        return p+pay

class TLS_Ext_PrettyPacketList(TLS_Ext_Unknown):
    """
    Dummy extension used for server_name/ALPN/NPN for a lighter representation:
    the final field is showed as a 1-line list rather than as lots of packets.
    XXX Define a new condition for packet lists in Packet._show_or_dump?
    """
    def _show_or_dump(self, dump=False, indent=3,
                      lvl="", label_lvl="", first_call=True):
        """ Reproduced from packet.py """
        ct = AnsiColorTheme() if dump else conf.color_theme
        s = "%s%s %s %s \n" % (label_lvl, ct.punct("###["),
                               ct.layer_name(self.name), ct.punct("]###"))
        for f in self.fields_desc[:-1]:
            ncol = ct.field_name
            vcol = ct.field_value
            fvalue = self.getfieldval(f.name)
            begn = "%s  %-10s%s " % (label_lvl+lvl, ncol(f.name),
                                     ct.punct("="),)
            reprval = f.i2repr(self,fvalue)
            if type(reprval) is str:
                reprval = reprval.replace("\n", "\n"+" "*(len(label_lvl)
                                                          +len(lvl)
                                                          +len(f.name)
                                                          +4))
            s += "%s%s\n" % (begn,vcol(reprval))
        f = self.fields_desc[-1]
        ncol = ct.field_name
        vcol = ct.field_value
        fvalue = self.getfieldval(f.name)
        begn = "%s  %-10s%s " % (label_lvl+lvl, ncol(f.name), ct.punct("="),)
        reprval = f.i2repr(self,fvalue)
        if type(reprval) is str:
            reprval = reprval.replace("\n", "\n"+" "*(len(label_lvl)
                                                      +len(lvl)
                                                      +len(f.name)
                                                      +4))
        s += "%s%s\n" % (begn,vcol(reprval))
        if self.payload:
            s += self.payload._show_or_dump(dump=dump, indent=indent,
                                lvl=lvl+(" "*indent*self.show_indent),
                                label_lvl=label_lvl, first_call=False)

        if first_call and not dump:
            print s
        else:
            return s


_tls_server_name_types = { 0: "host_name" }

class ServerName(Packet):
    name = "HostName"
    fields_desc = [ ByteEnumField("nametype", 0, _tls_server_name_types),
                    FieldLenField("namelen", None, length_of="servername"),
                    StrLenField("servername", "",
                                length_from=lambda pkt: pkt.namelen) ]
    def guess_payload_class(self, p):
        return Padding

class ServerListField(PacketListField):
    def i2repr(self, pkt, x):
        res = [p.servername for p in x]
        return "[%s]" % ", ".join(res)

class TLS_Ext_ServerName(TLS_Ext_PrettyPacketList):                 # RFC 4366
    name = "TLS Extension - Server Name"
    fields_desc = [ShortEnumField("type", 0, _tls_ext),
                   FieldLenField("len", None, length_of="servernames",
                                 adjust=lambda pkt,x: x+2),
                   FieldLenField("servernameslen", None,
                                 length_of="servernames"),
                   ServerListField("servernames", [], ServerName,
                                   length_from=lambda pkt: pkt.servernameslen)]


class TLS_Ext_MaxFragLen(TLS_Ext_Unknown):                          # RFC 4366
    name = "TLS Extension - Server Name"
    fields_desc = [ShortEnumField("type", 1, _tls_ext),
                   ShortField("len", None),
                   ByteEnumField("maxfraglen", 4, { 1: "2^9",
                                                    2: "2^10",
                                                    3: "2^11",
                                                    4: "2^12" }) ]


class TLS_Ext_ClientCertURL(TLS_Ext_Unknown):                       # RFC 4366
    name = "TLS Extension - Server Name"
    fields_desc = [ShortEnumField("type", 2, _tls_ext),
                   ShortField("len", None) ]


_tls_trusted_authority_types = {0: "pre_agreed",
                                1: "key_sha1_hash",
                                2: "x509_name",
                                3: "cert_sha1_hash" }

class TAPreAgreed(Packet):
    name = "Trusted authority - pre_agreed"
    fields_desc = [ ByteEnumField("idtype", 0, _tls_trusted_authority_types) ]
    def guess_payload_class(self, p):
        return Padding

class TAKeySHA1Hash(Packet):
    name = "Trusted authority - key_sha1_hash"
    fields_desc = [ ByteEnumField("idtype", 1, _tls_trusted_authority_types),
                    StrFixedLenField("id", None, 20) ]
    def guess_payload_class(self, p):
        return Padding

class TAX509Name(Packet):
    """
    XXX Section 3.4 of RFC 4366. Implement a more specific DNField
    rather than current StrLenField.
    """
    name = "Trusted authority - x509_name"
    fields_desc = [ ByteEnumField("idtype", 2, _tls_trusted_authority_types),
                    FieldLenField("dnlen", None, length_of="dn"),
                    StrLenField("dn", "", length_from=lambda pkt: pkt.dnlen) ]
    def guess_payload_class(self, p):
        return Padding

class TACertSHA1Hash(Packet):
    name = "Trusted authority - cert_sha1_hash"
    fields_desc = [ ByteEnumField("idtype", 3, _tls_trusted_authority_types),
                    StrFixedLenField("id", None, 20) ]
    def guess_payload_class(self, p):
        return Padding

_tls_trusted_authority_cls = {0: TAPreAgreed,
                              1: TAKeySHA1Hash,
                              2: TAX509Name,
                              3: TACertSHA1Hash }

class _TAListField(PacketListField):
    """
    Specific version that selects the right Trusted Authority (previous TA*)
    class to be used for dissection based on idtype.
    """
    def m2i(self, pkt, m):
        idtype = ord(m[0])
        cls = self.cls
        if _tls_trusted_authority_cls.has_key(idtype):
            cls = _tls_trusted_authority_cls[idtype]
        return cls(m)

class TLS_Ext_TrustedCAInd(TLS_Ext_Unknown):                        # RFC 4366
    name = "TLS Extension - Trusted CA Indication"
    fields_desc = [ShortEnumField("type", 3, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("talen", None, length_of="ta"),
                   _TAListField("ta", [], Raw,
                                length_from=lambda pkt: pkt.talen) ]


class TLS_Ext_TruncatedHMAC(TLS_Ext_Unknown):                       # RFC 4366
    name = "TLS Extension - Truncated HMAC"
    fields_desc = [ShortEnumField("type", 4, _tls_ext),
                   ShortField("len", None) ]


class ResponderID(Packet):
    name = "Responder ID structure"
    fields_desc = [ FieldLenField("respidlen", None, length_of="respid"),
                    StrLenField("respid", "",
                                length_from=lambda pkt: pkt.respidlen)]
    def guess_payload_class(self, p):
        return Padding

class OCSPStatusRequest(Packet):
    """
    This is the structure defined in RFC 6066, not in RFC 6960!
    """
    name = "OCSPStatusRequest structure"
    fields_desc = [ FieldLenField("respidlen", None, length_of="respid"),
                    PacketListField("respid", [], ResponderID,
                                    length_from=lambda pkt: pkt.respidlen),
                    FieldLenField("reqextlen", None, length_of="reqext"),
                    PacketField("reqext", "", X509_Extensions) ]
    def guess_payload_class(self, p):
        return Padding

_cert_status_type = { 1: "ocsp" }
_cert_status_req_cls  = { 1: OCSPStatusRequest }

class _StatusReqField(PacketListField):
    def m2i(self, pkt, m):
        idtype = pkt.stype
        cls = self.cls
        if _cert_status_req_cls.has_key(idtype):
            cls = _cert_status_req_cls[idtype]
        return cls(m)

class TLS_Ext_CSR(TLS_Ext_Unknown):                                 # RFC 4366
    name = "TLS Extension - Certificate Status Request"
    fields_desc = [ShortEnumField("type", 5, _tls_ext),
                   ShortField("len", None),
                   ByteEnumField("stype", None, _cert_status_type),
                   _StatusReqField("req", [], Raw,
                                  length_from=lambda pkt: pkt.len - 1) ]


class TLS_Ext_UserMapping(TLS_Ext_Unknown):                         # RFC 4681
    name = "TLS Extension - User Mapping"
    fields_desc = [ShortEnumField("type", 6, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("umlen", None, fmt="B", length_of="um"),
                   FieldListField("um", [],
                                  ByteField("umtype", 0),
                                  length_from=lambda pkt: pkt.umlen) ]


class TLS_Ext_ClientAuthz(TLS_Ext_Unknown):                         # RFC 5878
    """ XXX Unsupported """
    name = "TLS Extension - Client Authz"
    fields_desc = [ShortEnumField("type", 7, _tls_ext),
                   ShortField("len", None),
                   ]

class TLS_Ext_ServerAuthz(TLS_Ext_Unknown):                         # RFC 5878
    """ XXX Unsupported """
    name = "TLS Extension - Server Authz"
    fields_desc = [ShortEnumField("type", 8, _tls_ext),
                   ShortField("len", None),
                   ]


_tls_cert_types = { 0: "X.509", 1: "OpenPGP" }

class TLS_Ext_ClientCertType(TLS_Ext_Unknown):                      # RFC 5081
    name = "TLS Extension - Certificate Type (client version)"
    fields_desc = [ShortEnumField("type", 9, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("ctypeslen", None, length_of="ctypes"),
                   FieldListField("ctypes", [0, 1],
                                  ByteEnumField("certtypes", None,
                                                _tls_cert_types),
                                  length_from=lambda pkt: pkt.ctypeslen) ]

class TLS_Ext_ServerCertType(TLS_Ext_Unknown):                      # RFC 5081
    name = "TLS Extension - Certificate Type (server version)"
    fields_desc = [ShortEnumField("type", 9, _tls_ext),
                   ShortField("len", None),
                   ByteEnumField("ctype", None, _tls_cert_types) ]

def _TLS_Ext_CertTypeDispatcher(m, *args, **kargs):
    """
    We need to select the correct one on dissection. We use the length for
    that, as 1 for client version would emply an empty list.
    """
    l = struct.unpack("!H", m[2:4])[0]
    if l == 1:
        cls = TLS_Ext_ServerCertType
    else:
        cls = TLS_Ext_ClientCertType
    return cls(m, *args, **kargs)


class TLS_Ext_SupportedEllipticCurves(TLS_Ext_Unknown):             # RFC 4492
    name = "TLS Extension - Supported Elliptic Curves"
    fields_desc = [ShortEnumField("type", 10, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("ecllen", None, length_of="ecl"),
                   FieldListField("ecl", [],
                                    ShortEnumField("nc", None,
                                                   _tls_named_curves),
                                    length_from=lambda pkt: pkt.ecllen) ]


_tls_ecpoint_format = { 0: "uncompressed",
                        1: "ansiX962_compressed_prime",
                        2: "ansiX962_compressed_char2" }

class TLS_Ext_SupportedPointFormat(TLS_Ext_Unknown):                # RFC 4492
    name = "TLS Extension - Supported Point Format"
    fields_desc = [ShortEnumField("type", 11, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("ecpllen", None, fmt="B", length_of="ecpl"),
                   FieldListField("ecpl", [0],
                                    ByteEnumField("nc", None,
                                                  _tls_ecpoint_format),
                                    length_from=lambda pkt: pkt.ecpllen) ]


class TLS_Ext_SignatureAlgorithms(TLS_Ext_Unknown):                 # RFC 5246
    name = "TLS Extension - Signature Algorithms"
    fields_desc = [ShortEnumField("type", 13, _tls_ext),
                   ShortField("len", None),
                   SigAndHashAlgsLenField("sig_algs_len", None,
                                          length_of="sig_algs"),
                   SigAndHashAlgsField("sig_algs", [],
                                       EnumField("hash_sig", None,
                                                    _tls_hash_sig),
                                       length_from=
                                           lambda pkt: pkt.sig_algs_len) ]


class TLS_Ext_Heartbeat(TLS_Ext_Unknown):                           # RFC 6520
    name = "TLS Extension - Heartbeat"
    fields_desc = [ShortEnumField("type", 0x0f, _tls_ext),
                   ShortField("len", None),
                   ByteEnumField("heartbeat_mode", 2,
                       { 1: "peer_allowed_to_send",
                         2: "peer_not_allowed_to_send" }) ]


class ProtocolName(Packet):
    name = "Protocol Name"
    fields_desc = [ FieldLenField("len", None, fmt='B', length_of="protocol"),
                    StrLenField("protocol", "",
                                length_from=lambda pkt: pkt.len)]
    def guess_payload_class(self, p):
        return Padding

class ProtocolListField(PacketListField):
    def i2repr(self, pkt, x):
        res = [p.protocol for p in x]
        return "[%s]" % ", ".join(res)

class TLS_Ext_ALPN(TLS_Ext_PrettyPacketList):                       # RFC 7301
    name = "TLS Extension - Application Layer Protocol Negotiation"
    fields_desc = [ShortEnumField("type", 0x10, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("protocolslen", None, length_of="protocols"),
                   ProtocolListField("protocols", [], ProtocolName,
                                     length_from=lambda pkt:pkt.protocolslen) ]


class TLS_Ext_Padding(TLS_Ext_Unknown):                             # RFC 7685
    name = "TLS Extension - Padding"
    fields_desc = [ShortEnumField("type", 0x15, _tls_ext),
                   FieldLenField("len", None, length_of="padding"),
                   StrLenField("padding", "",
                               length_from=lambda pkt: pkt.len) ]


class TLS_Ext_SessionTicket(TLS_Ext_Unknown):                       # RFC 5077
    """
    RFC 5077 updates RFC 4507 according to most implementations, which do not
    use another (useless) 'ticketlen' field after the global 'len' field.
    """
    name = "TLS Extension - Session Ticket"
    fields_desc = [ShortEnumField("type", 0x23, _tls_ext),
                   FieldLenField("len", None, length_of="ticket"),
                   StrLenField("ticket", "",
                               length_from=lambda pkt: pkt.len) ]


class TLS_Ext_NPN(TLS_Ext_PrettyPacketList):
    """
    Defined in RFC-draft-agl-tls-nextprotoneg-03. Deprecated in favour of ALPN.
    """
    name = "TLS Extension - Next Protocol Negotiation"
    fields_desc = [ShortEnumField("type", 0x3374, _tls_ext),
                   FieldLenField("len", None, length_of="protocols"),
                   ProtocolListField("protocols", [], ProtocolName,
                                     length_from=lambda pkt:pkt.len) ]


class TLS_Ext_RenegotiationInfo(TLS_Ext_Unknown):                   # RFC 5746
    name = "TLS Extension - Renegotiation Indication"
    fields_desc = [ShortEnumField("type", 0xff01, _tls_ext),
                   ShortField("len", None),
                   FieldLenField("reneg_conn_len", None, fmt='B',
                                 length_of="renegotiated_connection"),
                   StrLenField("renegotiated_connection", "",
                               length_from=lambda pkt: pkt.reneg_conn_len) ]


_tls_ext_cls = { 0: TLS_Ext_ServerName,
                 1: TLS_Ext_MaxFragLen,
                 2: TLS_Ext_ClientCertURL,
                 3: TLS_Ext_TrustedCAInd,
                 4: TLS_Ext_TruncatedHMAC,
                 5: TLS_Ext_CSR,
                 6: TLS_Ext_UserMapping,
                 7: TLS_Ext_ClientAuthz,
                 8: TLS_Ext_ServerAuthz,
                 9: _TLS_Ext_CertTypeDispatcher,
                10: TLS_Ext_SupportedEllipticCurves,
                11: TLS_Ext_SupportedPointFormat,
                13: TLS_Ext_SignatureAlgorithms,
                0x0f: TLS_Ext_Heartbeat,
                0x10: TLS_Ext_ALPN,
                0x15: TLS_Ext_Padding,
                0x23: TLS_Ext_SessionTicket,
                0x3374: TLS_Ext_NPN,
                0xff01: TLS_Ext_RenegotiationInfo
                }


class _ExtensionsLenField(FieldLenField):
    """
    This field provides the first half of extensions support implementation
    as defined in RFC 3546. The second is provided by _ExtensionsField. Both
    are used as the last fields at the end of ClientHello messages.

    The idea is quite simple:
    - dissection : the _ExtensionsLenField will compute the remaining length of
    the message based on the value of a provided field (for instance 'msglen'
    in ClientHello) and a list of other fields that are considered "shifters".
    This shifters are length fields of some vectors. The sum of their value
    will be substracted to the one of the main field. If the result is
    positive, this means that extensions are present and the
    _ExtensionsLenField behaves just like a normal FieldLenField. If the value
    is null, invalid or not sufficient to grab a length, the getfield method of
    the field will simply return a 0 value without "eating" bytes from current
    string. In a sense, the field is always present (which means that its value
    is available for the _ExtensionsField field) but the behavior during
    dissection is conditional. Then, the _ExtensionsField uses the length value
    from the _ExtensionsLenField, to know how much data it should grab (TLS
    extension is basically a vector). If no extensions are present, the length
    field will have a null value and nothing will be grabbed.

    - build: during build, if some extensions are provided, the
    _ExtensionsLenField will automatically access the whole length and use it
    if the user does not provide a specific value. Now, if no extensions are
    available and the user does not provide a specific value, nothing is added
    during the build, i.e. no length field with a null value will appear. As a
    side note, this is also the case for the rebuild of a dissected packet: if
    the initial packet had a length field with a null value, one will be built.
    If no length field was was present, nothing is added, i.e. a rebuilt
    dissected packet will look like the original. Another side note is that the
    shifters allow us to decide if there is an extension vector but the length
    of that vector is grabbed from the value of the 2 first bytes, not from the
    value computed from shifters and msglen.
    """
    __slots__ = ["lfld", "shifters"]
    def __init__(self, name, default,
                 lfld, shifters=[],
                 fmt="!H", length_of=None):
        FieldLenField.__init__(self, name, default,
                               fmt=fmt, length_of=length_of)
        self.lfld = lfld
        self.shifters = shifters

    def getfield(self, pkt, s):
        # compute the length of remaining data to see if there are ext
        l = getattr(pkt, self.lfld)
        for fname in self.shifters:
            if type(fname) is int:
                l -= fname
            else:
                l -= getattr(pkt, fname)

        if l is None or l <= 0 or l < self.sz:
            return s, None  # let's consider there's no extensions

        return Field.getfield(self, pkt, s)

    def addfield(self, pkt, s, i):
        if i is None:
            if self.length_of is not None:
                fld,fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
                i = self.adjust(pkt, f)
                if i == 0: # for correct build if no ext and not explicitly 0
                    return s
        return s + struct.pack(self.fmt, i)

class _ExtensionsField(StrLenField):
    """
    See ExtensionsLenField documentation.
    """
    islist=1
    holds_packets=1

    def i2len(self, pkt, i):
        if i is None:
            return 0
        return len(self.i2m(pkt, i))

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        if l is None:
            return s, []
        return s[l:], self.m2i(pkt, s[:l])

    def i2m(self, pkt, i):
        if i is None:
            return ""
        return "".join(map(str, i))

    def m2i(self, pkt, m):
        res = []
        while m:
            t = struct.unpack("!H", m[:2])[0]
            l = struct.unpack("!H", m[2:4])[0]
            cls = _tls_ext_cls.get(t, TLS_Ext_Unknown)
            res.append(cls(m[:l+4], tls_session=pkt.tls_session))
            m = m[l+4:]
        return res


###############################################################################
### ClientHello                                                             ###
###############################################################################

class TLSClientHello(_TLSHandshake):
    """
    TLS ClientHello, with abilities to handle extensions.

    The Random structure follows the RFC 5246: while it is 32-byte long,
    many implementations use the first 4 bytes as a gmt_unix_time, and then
    the remaining 28 byts should be completely random. This was designed in
    order to (sort of) mitigate broken RNGs. If you prefer to show the full
    32 random bytes without any GMT time, just comment in/out the lines below.
    """
    name = "TLS Handshake - Client Hello"
    fields_desc = [ ByteEnumField("msgtype", 1, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    _TLSVersionField("version", 0x0303, _tls_version),

                    #_TLSRandomBytesField("random_bytes", None, 32),
                    _GMTUnixTimeField("gmt_unix_time", None),
                    _TLSRandomBytesField("random_bytes", None, 28),

                    FieldLenField("sidlen", None, fmt="B", length_of="sid"),
                    _SessionIDField("sid", "",
                                    length_from=lambda pkt:pkt.sidlen),

                    FieldLenField("cipherslen", None, fmt="!H",
                                  length_of="ciphers"),
                    _CipherSuitesField("ciphers",
                                       [TLS_DHE_RSA_WITH_AES_128_CBC_SHA],
                                       _tls_cipher_suites, itemfmt="!H",
                                       length_from=lambda pkt: pkt.cipherslen),

                    FieldLenField("complen", None, fmt="B", length_of="comp"),
                    _CompressionMethodsField("comp", [0],
                                             _tls_compression_algs,
                                             itemfmt="B",
                                             length_from=
                                                 lambda pkt: pkt.complen),

                    _ExtensionsLenField("extlen", None, "msglen",
                                       shifters = ["sidlen", "cipherslen",
                                                   "complen", 38],
                                       length_of="ext"),
                    _ExtensionsField("ext", None,
                                     length_from=lambda pkt: pkt.extlen) ]

    def post_build(self, p, pay):
        if self.random_bytes is None:
            p = p[:10] + randstring(28) + p[10+28:]
        return super(TLSClientHello, self).post_build(p, pay)

    def tls_session_update(self, msg_str):
        """
        Either for parsing or building, we store the client_random
        along with the raw string representing this handshake message.
        """
        self.tls_session.advertised_tls_version = self.version
        self.random_bytes = msg_str[10:38]
        self.tls_session.client_random = (struct.pack('!I',
                                                      self.gmt_unix_time) +
                                          self.random_bytes)
        self.tls_session.handshake_messages.append(msg_str)
        self.tls_session.handshake_messages_parsed.append(self)


###############################################################################
### ServerHello                                                             ###
###############################################################################

class TLSServerHello(TLSClientHello):
    """
    TLS ServerHello, with abilities to handle extensions.

    The Random structure follows the RFC 5246: while it is 32-byte long,
    many implementations use the first 4 bytes as a gmt_unix_time, and then
    the remaining 28 byts should be completely random. This was designed in
    order to (sort of) mitigate broken RNGs. If you prefer to show the full
    32 random bytes without any GMT time, just comment in/out the lines below.
    """
    name = "TLS Handshake - Server Hello"
    fields_desc = [ ByteEnumField("msgtype", 2, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    _TLSVersionField("version", None, _tls_version),

                    #_TLSRandomBytesField("random_bytes", None, 32),
                    _GMTUnixTimeField("gmt_unix_time", None),
                    _TLSRandomBytesField("random_bytes", None, 28),

                    FieldLenField("sidlen", None, length_of="sid", fmt="B"),
                    _SessionIDField("sid", "",
                                   length_from = lambda pkt: pkt.sidlen),

                    EnumField("cipher", None, _tls_cipher_suites),
                    _CompressionMethodsField("comp", [0],
                                             _tls_compression_algs,
                                             itemfmt="B",
                                             length_from=lambda pkt: 1),

                    _ExtensionsLenField("extlen", None, "msglen",
                                        shifters = ["sidlen", 38],
                                        length_of="ext"),
                    _ExtensionsField("ext", [],
                                     length_from=lambda pkt: pkt.extlen) ]

    def tls_session_update(self, msg_str):
        """
        Either for parsing or building, we store the server_random
        along with the raw string representing this handshake message.
        We also store the session_id, the cipher suite (if recognized),
        the compression method, and finally we instantiate the pending write
        and read connection states. Usually they get updated later on in the
        negotiation when we learn the session keys, and eventually they
        are committed once a ChangeCipherSpec has been sent/received.
        """
        self.tls_session.tls_version = self.version
        self.random_bytes = msg_str[10:38]
        self.tls_session.server_random = (struct.pack('!I',
                                                      self.gmt_unix_time) +
                                          self.random_bytes)
        self.tls_session.handshake_messages.append(msg_str)
        self.tls_session.handshake_messages_parsed.append(self)

        self.tls_session.sid = self.sid

        if self.cipher:
            cs_val = self.cipher
            if not _tls_cipher_suites_cls.has_key(cs_val):
                warning("Unknown cipher suite %d from ServerHello" % cs_val)
                # we do not try to set a default nor stop the execution
            else:
                cs_cls = _tls_cipher_suites_cls[cs_val]

        if self.comp:
            comp_val = self.comp[0]
            if not _tls_compression_algs_cls.has_key(comp_val):
                err = "Unknown compression alg %d from ServerHello" % comp_val
                warning(err)
                comp_val = 0
            comp_cls = _tls_compression_algs_cls[comp_val]

        connection_end = self.tls_session.connection_end
        self.tls_session.pwcs = writeConnState(ciphersuite=cs_cls,
                                               compression_alg=comp_cls,
                                               connection_end=connection_end,
                                               tls_version=self.version)
        self.tls_session.prcs = readConnState(ciphersuite=cs_cls,
                                              compression_alg=comp_cls,
                                              connection_end=connection_end,
                                              tls_version=self.version)


###############################################################################
### Certificate                                                             ###
###############################################################################

class _ASN1CertLenField(FieldLenField):
    """
    This is mostly a 3-byte FieldLenField.
    """
    def __init__(self, name, default, length_of=None, adjust=lambda pkt, x: x):
        self.length_of = length_of
        self.adjust = adjust
        Field.__init__(self, name, default, fmt="!I")

    def i2m(self, pkt, x):
        if x is None:
            if self.length_of is not None:
                fld,fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
                x = self.adjust(pkt, f)
        return x

    def addfield(self, pkt, s, val):
        return s + struct.pack(self.fmt, self.i2m(pkt,val))[1:4]

    def getfield(self, pkt, s):
        return s[3:], self.m2i(pkt, struct.unpack(self.fmt, "\x00" + s[:3])[0])


class _ASN1CertListField(StrLenField):
    islist = 1
    def i2len(self, pkt, i):
        if i is None:
            return 0
        return len(self.i2m(pkt, i))

    def getfield(self, pkt, s):
        """
        Extract Certs in a loop.
        XXX We should providesafeguards when trying to parse a Cert.
        """
        l = None
        if self.length_from is not None:
            l = self.length_from(pkt)

        lst = []
        ret = ""
        m = s
        if l is not None:
            m, ret = s[:l], s[l:]
        while m:
            clen = struct.unpack("!I", '\x00' + m[:3])[0]
            lst.append((clen, Cert(m[3:3 + clen])))
            m = m[3 + clen:]
        return m + ret, lst

    def i2m(self, pkt, i):
        def i2m_one(i):
            if type(i) is str:
                return i
            if isinstance(i, Cert):
                s = i.der
                l = struct.pack("!I", len(s))[1:4]
                return l + s

            (l, s) = i
            if isinstance(s, Cert):
                s = s.der
            return struct.pack("!I", l)[1:4] + s

        if i is None:
            return ""
        if type(i) is str:
            return i
        if isinstance(i, Cert):
            i = [i]
        return "".join(map(lambda x: i2m_one(x), i))

    def any2i(self, pkt, x):
        return x


class TLSCertificate(_TLSHandshake):
    """
    XXX We do not support RFC 5081, i.e. OpenPGP certificates.
    """
    name = "TLS Handshake - Certificate"
    fields_desc = [ ByteEnumField("msgtype", 11, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    _ASN1CertLenField("certslen", None, length_of="certs"),
                    _ASN1CertListField("certs", [],
                                      length_from = lambda pkt: pkt.certslen) ]

    def post_dissection_tls_session_update(self, msg_str):
        connection_end = self.tls_session.connection_end
        if connection_end == "client":
            self.tls_session.server_certs = map(lambda x: x[1], self.certs)
        else:
            self.tls_session.client_certs = map(lambda x: x[1], self.certs)
        self.tls_session.handshake_messages.append(msg_str)
        self.tls_session.handshake_messages_parsed.append(self)


###############################################################################
### ServerKeyExchange                                                       ###
###############################################################################

class TLSServerKeyExchange(_TLSHandshake):
    name = "TLS Handshake - Server Key Exchange"
    fields_desc = [ ByteEnumField("msgtype", 12, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    _TLSServerParamsField("params", None,
                        length_from=lambda pkt: pkt.msglen),
                    _TLSSignatureField("sig", None,
                        length_from=lambda pkt: pkt.msglen - len(pkt.params)) ]

    def build(self, *args, **kargs):
        """
        We overload build() method in order to provide a valid default value
        for params based on TLS session if not provided. This cannot be done by
        overriding i2m() because the method is called on a copy of the packet.

        The 'params' field is built according to key_exchange.server_kx_msg_cls
        which should have been set after receiving a cipher suite in a
        previous ServerHello. Usual cases are:
        - None: for RSA encryption or fixed FF/ECDH. This should never happen,
          as no ServerKeyExchange should be generated in the first place.
        - ServerDHParams: for ephemeral FFDH. In that case, the parameter to
          server_kx_msg_cls does not matter.
        - ServerECDH*Params: for ephemeral ECDH. There are actually three
          classes, which are dispatched by _tls_server_ecdh_cls_guess on
          the first byte retrieved. The default here is "\03", which
          corresponds to ServerECDHNamedCurveParams (implicit curves).

        When the Server*DHParams are built via .fill_missing(), the session
        server_kx_params and client_kx_params will be updated accordingly.
        """
        fval = self.getfieldval("params")
        if fval is None:
            s = self.tls_session
            if s.pwcs:
                if s.pwcs.key_exchange.export:
                    cls = ServerRSAParams(tls_session=s)
                else:
                    cls = s.pwcs.key_exchange.server_kx_msg_cls("\x03")
                    cls = cls(tls_session=s)
                try:
                    cls.fill_missing()
                except:
                    pass
            else:
                cls = Raw()
            self.params = cls

        fval = self.getfieldval("sig")
        if fval is None:
            s = self.tls_session
            if s.pwcs:
                if not s.pwcs.key_exchange.anonymous:
                    p = self.params
                    if p is None:
                        p = ""
                    m = s.client_random + s.server_random + str(p)
                    cls = _TLSSignature(tls_session=s)
                    cls._update_sig(m, s.server_key)
                else:
                    cls = Raw()
            else:
                cls = Raw()
            self.sig = cls

        return _TLSHandshake.build(self, *args, **kargs)

    def post_dissection(self, pkt):
        """
        While previously dissecting Server*DHParams, the session
        server_kx_params and client_kx_params should have been updated.

        XXX Add a 'fixed_dh' OR condition to the 'anonymous' test.
        """
        s = self.tls_session
        if s.prcs and s.prcs.key_exchange.anonymous:
            print "USELESS SERVER KEY EXCHANGE"
        if (s.client_random and s.server_random and
            s.server_certs and len(s.server_certs) > 0):
            m = s.client_random + s.server_random + str(self.params)
            sig_test = self.sig._verify_sig(m, s.server_certs[0])
            if not sig_test:
                print "INVALID SERVER KEY EXCHANGE SIGNATURE"


###############################################################################
### CertificateRequest                                                      ###
###############################################################################

_tls_client_certificate_types =  {  1: "rsa_sign",
                                    2: "dss_sign",
                                    3: "rsa_fixed_dh",
                                    4: "dss_fixed_dh",
                                    5: "rsa_ephemeral_dh_RESERVED",
                                    6: "dss_ephemeral_dh_RESERVED",
                                   20: "fortezza_dms_RESERVED",
                                   64: "ecdsa_sign",
                                   65: "rsa_fixed_ecdh",
                                   66: "ecdsa_fixed_ecdh" }


class _CertTypesField(_CipherSuitesField):
    pass

class _CertAuthoritiesField(StrLenField):
    """
    XXX Rework this with proper ASN.1 parsing.
    """
    islist = 1

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        return s[l:], self.m2i(pkt, s[:l])

    def m2i(self, pkt, m):
        res = []
        while len(m) > 1:
            l = struct.unpack("!H", m[:2])[0]
            if len(m) < l + 2:
                res.append((l, m[2:]))
                break
            dn = m[2:2+l]
            res.append((l, dn))
            m = m[2+l:]
        return res

    def i2m(self, pkt, i):
        return "".join(map(lambda (x,y): struct.pack("!H", x) + y, i))

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val)

    def i2len(self, pkt, val):
        if val is None:
            return 0
        else:
            return len(self.i2m(pkt, val))


class TLSCertificateRequest(_TLSHandshake):
    name = "TLS Handshake - Certificate Request"
    fields_desc = [ ByteEnumField("msgtype", 13, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    FieldLenField("ctypeslen", None, fmt="B",
                                  length_of="ctypes"),
                    _CertTypesField("ctypes", [],
                                    _tls_client_certificate_types,
                                    itemfmt="!B",
                                    length_from=lambda pkt: pkt.ctypeslen),
                    SigAndHashAlgsLenField("sig_algs_len", None,
                                           length_of="sig_algs"),
                    SigAndHashAlgsField("sig_algs", [],
                                        EnumField("hash_sig", None,
                                                     _tls_hash_sig),
                                        length_from=
                                            lambda pkt: pkt.sig_algs_len),
                    FieldLenField("certauthlen", None, fmt="!H",
                                  length_of="certauth"),
                    _CertAuthoritiesField("certauth", [],
                                          length_from=
                                              lambda pkt: pkt.certauthlen) ]


###############################################################################
### ServerHelloDone                                                         ###
###############################################################################

class TLSServerHelloDone(_TLSHandshake):
    name = "TLS Handshake - Server Hello Done"
    fields_desc = [ ByteEnumField("msgtype", 14, _tls_handshake_type),
                    ThreeBytesField("msglen", None) ]


###############################################################################
### CertificateVerify                                                       ###
###############################################################################

class TLSCertificateVerify(_TLSHandshake):
    name = "TLS Handshake - Certificate Verify"
    fields_desc = [ ByteEnumField("msgtype", 15, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    _TLSSignatureField("sig", None,
                                 length_from = lambda pkt: pkt.msglen) ]

    def build(self, *args, **kargs):
        sig = self.getfieldval("sig")
        if sig is None:
            s = self.tls_session
            m = "".join(s.handshake_messages)
            self.sig = _TLSSignature(tls_session=s)
            self.sig._update_sig(m, s.client_key)
        return _TLSHandshake.build(self, *args, **kargs)

    def post_dissection(self, pkt):
        s = self.tls_session
        m = "".join(s.handshake_messages)
        if s.client_certs and len(s.client_certs) > 0:
            sig_test = self.sig._verify_sig(m, s.client_certs[0])
            if not sig_test:
                print "INVALID CERTIFICATE VERIFY SIGNATURE"


###############################################################################
### ClientKeyExchange                                                       ###
###############################################################################

class _TLSCKExchKeysField(PacketField):
    __slots__ = ["length_from"]
    holds_packet = 1
    def __init__(self, name, length_from=None, remain=0):
        self.length_from = length_from
        PacketField.__init__(self, name, None, None, remain=remain)

    def m2i(self, pkt, m):
        """
        The client_kx_msg may be either None, EncryptedPreMasterSecret
        (for RSA encryption key exchange), ClientDiffieHellmanPublic,
        or ClientECDiffieHellmanPublic. When either one of them gets
        dissected, the session context is updated accordingly.
        """
        l = self.length_from(pkt)
        tbd, rem = m[:l], m[l:]

        s = pkt.tls_session
        cls = None

        if s.prcs and s.prcs.key_exchange:
            cls = s.prcs.key_exchange.client_kx_msg_cls

        if cls is None:
            return Raw(tbd)/Padding(rem)

        return cls(tbd, tls_session=s)/Padding(rem)


class TLSClientKeyExchange(_TLSHandshake):
    """
    This class mostly works like TLSServerKeyExchange and its 'params' field.
    """
    name = "TLS Handshake - Client Key Exchange"
    fields_desc = [ ByteEnumField("msgtype", 16, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    _TLSCKExchKeysField("exchkeys",
                                        length_from = lambda pkt: pkt.msglen) ]

    def build(self, *args, **kargs):
        fval = self.getfieldval("exchkeys")
        if fval is None:
            s = self.tls_session
            if s.prcs:
                cls = s.prcs.key_exchange.client_kx_msg_cls
                cls = cls(tls_session=s)
            else:
                cls = Raw()
            self.exchkeys = cls
        return _TLSHandshake.build(self, *args, **kargs)


###############################################################################
### Finished                                                                ###
###############################################################################

class _VerifyDataField(StrLenField):
    def getfield(self, pkt, s):
        if pkt.tls_session.tls_version == 0x300:
            sep = 36
        else:
            sep = 12
        return s[sep:], s[:sep]

class TLSFinished(_TLSHandshake):
    name = "TLS Handshake - Finished"
    fields_desc = [ ByteEnumField("msgtype", 20, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    _VerifyDataField("vdata", None) ]

    def build(self, *args, **kargs):
        fval = self.getfieldval("vdata")
        if fval is None:
            s = self.tls_session
            handshake_msg = "".join(s.handshake_messages)
            ms = s.master_secret
            con_end = s.connection_end
            self.vdata = s.wcs.prf.compute_verify_data(con_end, "write",
                                                       handshake_msg, ms)
        return _TLSHandshake.build(self, *args, **kargs)

    def post_dissection(self, pkt):
        s = self.tls_session
        handshake_msg = "".join(s.handshake_messages)
        if s.master_secret is not None:
            ms = s.master_secret
            con_end = s.connection_end
            verify_data = s.rcs.prf.compute_verify_data(con_end, "read",
                                                        handshake_msg, ms)
            if self.vdata != verify_data:
                print "INVALID TLS FINISHED RECEIVED"


## Additional handshake messages

###############################################################################
### HelloVerifyRequest                                                      ###
###############################################################################

class TLSHelloVerifyRequest(_TLSHandshake):
    """
    Defined for DTLS, see RFC 6347.
    """
    name = "TLS Handshake - Hello Verify Request"
    fields_desc = [ ByteEnumField("msgtype", 21, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    FieldLenField("cookielen", None,
                                  fmt="B", length_of="cookie"),
                    StrLenField("cookie", "",
                                length_from=lambda pkt: pkt.cookielen) ]


###############################################################################
### CertificateURL                                                          ###
###############################################################################

_tls_cert_chain_types = { 0: "individual_certs",
                          1: "pkipath" }

class URLAndOptionalHash(Packet):
    name = "URLAndOptionHash structure for TLSCertificateURL"
    fields_desc = [ FieldLenField("urllen", None, length_of="url"),
                    StrLenField("url", "",
                                length_from=lambda pkt: pkt.urllen),
                    FieldLenField("hash_present", None,
                                  fmt="B", length_of="hash",
                                  adjust=lambda pkt,x: int(math.ceil(x/20.))),
                    StrLenField("hash", "",
                                length_from=lambda pkt: 20*pkt.hash_present) ]
    def guess_payload_class(self, p):
        return Padding

class TLSCertificateURL(_TLSHandshake):
    """
    Defined in RFC 4366. PkiPath structure of section 8 is not implemented yet.
    """
    name = "TLS Handshake - Certificate URL"
    fields_desc = [ ByteEnumField("msgtype", 21, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    ByteEnumField("certchaintype", None, _tls_cert_chain_types),
                    FieldLenField("uahlen", None, length_of="uah"),
                    PacketListField("uah", [], URLAndOptionalHash,
                                    length_from=lambda pkt: pkt.uahlen) ]


###############################################################################
### CertificateStatus                                                       ###
###############################################################################

class ThreeBytesLenField(FieldLenField):
    def __init__(self, name, default,  length_of=None, adjust=lambda pkt, x:x):
        FieldLenField.__init__(self, name, default, length_of=length_of,
                               fmt='!I', adjust=adjust)
    def i2repr(self, pkt, x):
        if x is None:
            return 0
        return repr(self.i2h(pkt,x))
    def addfield(self, pkt, s, val):
        return s+struct.pack(self.fmt, self.i2m(pkt,val))[1:4]
    def getfield(self, pkt, s):
        return  s[3:], self.m2i(pkt, struct.unpack(self.fmt, "\x00"+s[:3])[0])

_cert_status_cls  = { 1: OCSP_Response }

class _StatusField(PacketField):
    def m2i(self, pkt, m):
        idtype = pkt.status_type
        cls = self.cls
        if _cert_status_cls.has_key(idtype):
            cls = _cert_status_cls[idtype]
        return cls(m)

class TLSCertificateStatus(_TLSHandshake):
    name = "TLS Handshake - Certificate Status"
    fields_desc = [ ByteEnumField("msgtype", 22, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    ByteEnumField("status_type", 1, _cert_status_type),
                    ThreeBytesLenField("responselen", None,
                                       length_of="response"),
                    _StatusField("response", None, Raw) ]


###############################################################################
### SupplementalData                                                        ###
###############################################################################

class SupDataEntry(Packet):
    name = "Supplemental Data Entry - Generic"
    fields_desc = [ ShortField("sdtype", None),
                    FieldLenField("len", None, length_of="data"),
                    StrLenField("data", "",
                                length_from=lambda pkt:pkt.len) ]
    def guess_payload_class(self, p):
        return Padding

class UserMappingData(Packet):
    name = "User Mapping Data"
    fields_desc = [ ByteField("version", None),
                    FieldLenField("len", None, length_of="data"),
                    StrLenField("data", "",
                                length_from=lambda pkt: pkt.len)]
    def guess_payload_class(self, p):
        return Padding

class SupDataEntryUM(Packet):
    name = "Supplemental Data Entry - User Mapping"
    fields_desc = [ ShortField("sdtype", None),
                    FieldLenField("len", None, length_of="data",
                                  adjust=lambda pkt, x: x+2),
                    FieldLenField("dlen", None, length_of="data"),
                    PacketListField("data", [], UserMappingData,
                                    length_from=lambda pkt:pkt.dlen) ]
    def guess_payload_class(self, p):
        return Padding

class TLSSupplementalData(_TLSHandshake):
    name = "TLS Handshake - Supplemental Data"
    fields_desc = [ ByteEnumField("msgtype", 23, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    ThreeBytesLenField("sdatalen", None, length_of="sdata"),
                    PacketListField("sdata", [], SupDataEntry,
                                    length_from=lambda pkt: pkt.sdatalen) ]


###############################################################################
### NewSessionTicket                                                        ###
###############################################################################

class Ticket(Packet):
    name = "Recommended Ticket Construction"
    fields_desc = [ StrFixedLenField("key_name", None, 16),
                    StrFixedLenField("iv", None, 16),
                    FieldLenField("estatelen", None, length_of="estate"),
                    StrLenField("estate", "",
                                length_from=lambda pkt: pkt.estatelen),
                    StrFixedLenField("mac", None, 32) ]

class TLSNewSessionTicket(_TLSHandshake):
    """
    XXX When knowing the right secret, we should be able to read the ticket.
    """
    name = "TLS Handshake - New Session Ticket"
    fields_desc = [ ByteEnumField("msgtype", 4, _tls_handshake_type),
                    ThreeBytesField("msglen", None),
                    IntField("lifetime", 0xffffffff),
                    FieldLenField("ticketlen", None, length_of="ticket"),
                    StrLenField("ticket", "",
                                length_from=lambda pkt: pkt.msglen) ]


###############################################################################
### All handshake messages defined in this module                           ###
###############################################################################

_tls_handshake_cls = { 0: TLSHelloRequest,          1: TLSClientHello,
                       2: TLSServerHello,           3: TLSHelloVerifyRequest,
                       4: TLSNewSessionTicket,      11: TLSCertificate,
                       12: TLSServerKeyExchange,    13: TLSCertificateRequest,
                       14: TLSServerHelloDone,      15: TLSCertificateVerify,
                       16: TLSClientKeyExchange,    20: TLSFinished,
                       21: TLSCertificateURL,       22: TLSCertificateStatus,
                       23: TLSSupplementalData }

