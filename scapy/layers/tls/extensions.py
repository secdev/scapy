## This file is part of Scapy
## Copyright (C) 2017 Maxence Tury
## This program is published under a GPLv2 license

"""
TLS handshake extensions.
"""

from scapy.fields import *
from scapy.packet import Packet, Raw, Padding
from scapy.layers.x509 import X509_Extensions
from scapy.layers.tls.basefields import _tls_version
from scapy.layers.tls.keyexchange import (_tls_named_curves,
                                          SigAndHashAlgsLenField,
                                          SigAndHashAlgsField, _tls_hash_sig)
from scapy.layers.tls.session import _GenericTLSSessionInheritance


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
    name = "TLS Extension - Max Fragment Length"
    fields_desc = [ShortEnumField("type", 1, _tls_ext),
                   ShortField("len", None),
                   ByteEnumField("maxfraglen", 4, { 1: "2^9",
                                                    2: "2^10",
                                                    3: "2^11",
                                                    4: "2^12" }) ]


class TLS_Ext_ClientCertURL(TLS_Ext_Unknown):                       # RFC 4366
    name = "TLS Extension - Client Certificate URL"
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


class TLS_Ext_EncryptThenMAC(TLS_Ext_Unknown):                      # RFC 7366
    name = "TLS Extension - Encrypt-then-MAC"
    fields_desc = [ShortEnumField("type", 0x16, _tls_ext),
                   ShortField("len", None) ]


class TLS_Ext_ExtendedMasterSecret(TLS_Ext_Unknown):                # RFC 7627
    name = "TLS Extension - Extended Master Secret"
    fields_desc = [ShortEnumField("type", 0x17, _tls_ext),
                   ShortField("len", None) ]


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
                0x16: TLS_Ext_EncryptThenMAC,
                0x17: TLS_Ext_ExtendedMasterSecret,
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
    If no length field was present, nothing is added, i.e. a rebuilt dissected
    packet will look like the original. Another side note is that the shifters
    allow us to decide if there is an extension vector but the length of that
    vector is grabbed from the value of the 2 first bytes, not from the value
    computed from shifters and msglen.
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



