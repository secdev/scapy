# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Secure Shell (SSH) Transport Layer Protocol

RFC 4250, 4251, 4252, 4253 and 4254
"""

from scapy.config import conf
from scapy.compat import plain_str
from scapy.fields import (
    BitLenField,
    ByteField,
    ByteEnumField,
    IntEnumField,
    IntField,
    PacketField,
    PacketListField,
    PacketLenField,
    FieldLenField,
    FieldListField,
    StrLenField,
    StrFixedLenField,
    StrNullField,
    YesNoByteField,
)
from scapy.packet import Packet, bind_bottom_up, bind_layers

from scapy.layers.inet import TCP


class StrCRLFField(StrNullField):
    DELIMITER = b"\r\n"


class _SSHHeaderField(FieldListField):
    def getfield(self, pkt, s):
        val = []
        while s:
            s, v = self.field.getfield(pkt, s)
            val.append(v)
            if v[:4] == b"SSH-":
                return s, val
        return s, val


# RFC 4251 - SSH Architecture
# This RFC defines some types

# RFC 4251 - sect 5


class _ComaStrField(StrLenField):
    islist = 1

    def m2i(self, pkt, x):
        return super(_ComaStrField, self).m2i(pkt, x).split(b",")

    def i2m(self, pkt, x):
        return super(_ComaStrField, self).i2m(pkt, b",".join(x))


class SSHString(Packet):
    fields_desc = [
        FieldLenField("length", None, length_of="value", fmt="!I"),
        StrLenField("value", 0, length_from=lambda pkt: pkt.length),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class SSHPacketStringField(PacketField):
    __slots__ = ["sub_cls"]

    def __init__(self, name, sub_cls):
        self.sub_cls = sub_cls
        super(SSHPacketStringField, self).__init__(name, SSHString(), SSHString)

    def m2i(self, pkt, x):
        x = super(SSHPacketStringField, self).m2i(pkt, x)
        x.value = self.sub_cls(x.value)
        return x


class NameList(Packet):
    fields_desc = [
        FieldLenField("length", None, length_of="names", fmt="!I"),
        _ComaStrField("names", [], length_from=lambda pkt: pkt.length),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class Mpint(Packet):
    fields_desc = [
        FieldLenField("length", None, length_of="value", fmt="!I"),
        BitLenField("value", 0, length_from=lambda pkt: pkt.length * 8),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


# RFC4250 - sect 4.1.2

_SSH_message_numbers = {
    # RFC4253 - SSH-TRANS
    1: "SSH_MSG_DISCONNECT",
    2: "SSH_MSG_IGNORE",
    3: "SSH_MSG_UNIMPLEMENTED",
    4: "SSH_MSG_DEBUG",
    5: "SSH_MSG_SERVICE_REQUEST",
    6: "SSH_MSG_SERVICE_ACCEPT",
    7: "SSH_MSG_EXT_INFO",  # RFC 8308
    8: "SSH_MSG_NEWCOMPRESS",
    20: "SSH_MSG_KEXINIT",
    21: "SSH_MSG_NEWKEYS",
    # Errata 152 of RFC4253
    30: "SSH_MSG_KEXDH_INIT",
    31: "SSH_MSG_KEXDH_REPLY",
    # RFC4252 - SSH-USERAUTH
    50: "SSH_MSG_USERAUTH_REQUEST",
    51: "SSH_MSG_USERAUTH_FAILURE",
    52: "SSH_MSG_USERAUTH_SUCCESS",
    53: "SSH_MSG_USERAUTH_BANNER",
    # RFC4254 - SSH-CONNECT
    80: "SSH_MSG_GLOBAL_REQUEST",
    81: "SSH_MSG_REQUEST_SUCCESS",
    82: "SSH_MSG_REQUEST_FAILURE",
    90: "SSH_MSG_CHANNEL_OPEN",
    91: "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
    92: "SSH_MSG_CHANNEL_OPEN_FAILURE",
    93: "SSH_MSG_CHANNEL_WINDOW_ADJUST",
    94: "SSH_MSG_CHANNEL_DATA",
    95: "SSH_MSG_CHANNEL_EXTENDED_DATA",
    96: "SSH_MSG_CHANNEL_EOF",
    97: "SSH_MSG_CHANNEL_CLOSE",
    98: "SSH_MSG_CHANNEL_REQUEST",
    99: "SSH_MSG_CHANNEL_SUCCESS",
    100: "SSH_MSG_CHANNEL_FAILURE",
}

# RFC4253 - sect 6

_SSH_messages = {}


def _SSHPayload(x, **kwargs):
    return _SSH_messages.get(x and x[0], conf.raw_layer)(x)


class SSH(Packet):
    name = "SSH - Binary Packet"
    fields_desc = [
        IntField("packet_length", None),
        ByteField("padding_length", None),
        PacketLenField(
            "pay",
            None,
            _SSHPayload,
            length_from=lambda pkt: pkt.packet_length - pkt.padding_length - 1,
        ),
        StrLenField("random_padding", b"", length_from=lambda pkt: pkt.padding_length),
        # StrField("mac", b""),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 4 and _pkt[:4] == b"SSH-":
            return SSHVersionExchange
        return cls

    def mysummary(self):
        if self.pay:
            if isinstance(self.pay, conf.raw_layer):
                return "SSH type " + str(self.pay.load[0]), [TCP, SSH]
            return "SSH " + self.pay.sprintf("%type%"), [TCP, SSH]
        return "SSH", [TCP, SSH]


# RFC4253 - sect 4.2


class SSHVersionExchange(Packet):
    name = "SSH - Protocol Version Exchange"
    fields_desc = [
        _SSHHeaderField(
            "lines",
            [],
            StrCRLFField("", b""),
        )
    ]

    def mysummary(self):
        return "SSH - Version Exchange %s" % plain_str(self.lines[-1]), [TCP]


# RFC4253 - sect 6.6

_SSH_certificates = {}
_SSH_publickeys = {}
_SSH_signatures = {}


class _SSHCertificate(PacketField):
    def m2i(self, pkt, x):
        return _SSH_certificates.get(pkt.format_identifier.value, self.cls)(x)


class _SSHPublicKey(PacketField):
    def m2i(self, pkt, x):
        return _SSH_publickeys.get(pkt.format_identifier.value, self.cls)(x)


class _SSHSignature(PacketField):
    def m2i(self, pkt, x):
        return _SSH_signatures.get(pkt.format_identifier.value, self.cls)(x)


class SSHCertificate(Packet):
    fields_desc = [
        PacketField("format_identifier", SSHString(), SSHString),
        _SSHCertificate("data", None, conf.raw_layer),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class SSHPublicKey(Packet):
    fields_desc = [
        PacketField("format_identifier", SSHString(), SSHString),
        _SSHPublicKey("data", None, conf.raw_layer),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class SSHSignature(Packet):
    fields_desc = [
        PacketField("format_identifier", SSHString(), SSHString),
        _SSHSignature("data", None, conf.raw_layer),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


# RFC4253 - sect 7.1


class SSHKexInit(Packet):
    fields_desc = [
        ByteEnumField("type", 20, _SSH_message_numbers),
        StrFixedLenField("cookie", b"", length=16),
        PacketField("kex_algorithms", NameList(), NameList),
        PacketField("server_host_key_algorithms", NameList(), NameList),
        PacketField("encryption_algorithms_client_to_server", NameList(), NameList),
        PacketField("encryption_algorithms_server_to_client", NameList(), NameList),
        PacketField("mac_algorithms_client_to_server", NameList(), NameList),
        PacketField("mac_algorithms_server_to_client", NameList(), NameList),
        PacketField("compression_algorithms_client_to_server", NameList(), NameList),
        PacketField("compression_algorithms_server_to_client", NameList(), NameList),
        PacketField("languages_client_to_server", NameList(), NameList),
        PacketField("languages_server_to_client", NameList(), NameList),
        YesNoByteField("first_kex_packet_follows", 0),
        IntField("reserved", 0),
    ]


_SSH_messages[20] = SSHKexInit

# RFC4253 - sect 7.3


class SSHNewKeys(Packet):
    fields_desc = [
        ByteEnumField("type", 21, _SSH_message_numbers),
    ]


_SSH_messages[21] = SSHNewKeys


# RFC4253 - sect 8


class SSHKexDHInit(Packet):
    fields_desc = [
        ByteEnumField("type", 30, _SSH_message_numbers),
        PacketField("e", Mpint(), Mpint),
    ]


_SSH_messages[30] = SSHKexDHInit


class SSHKexDHReply(Packet):
    fields_desc = [
        ByteEnumField("type", 31, _SSH_message_numbers),
        SSHPacketStringField("K_S", SSHPublicKey),
        PacketField("f", Mpint(), Mpint),
        SSHPacketStringField("H_hash", SSHSignature),
    ]


_SSH_messages[31] = SSHKexDHReply

# RFC4253 - sect 10


class SSHServiceRequest(Packet):
    fields_desc = [
        ByteEnumField("type", 5, _SSH_message_numbers),
        PacketField("service_name", SSHString(), SSHString),
    ]


_SSH_messages[5] = SSHServiceRequest


class SSHServiceAccept(Packet):
    fields_desc = [
        ByteEnumField("type", 6, _SSH_message_numbers),
        PacketField("service_name", SSHString(), SSHString),
    ]


_SSH_messages[6] = SSHServiceAccept

# RFC4253 - sect 11.1


class SSHDisconnect(Packet):
    fields_desc = [
        ByteEnumField("type", 1, _SSH_message_numbers),
        IntEnumField(
            "reason_code",
            0,
            {
                1: "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT",
                2: "SSH_DISCONNECT_PROTOCOL_ERROR",
                3: "SSH_DISCONNECT_KEY_EXCHANGE_FAILED",
                4: "SSH_DISCONNECT_RESERVED",
                5: "SSH_DISCONNECT_MAC_ERROR",
                6: "SSH_DISCONNECT_COMPRESSION_ERROR",
                7: "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE",
                8: "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED",
                9: "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE",
                10: "SSH_DISCONNECT_CONNECTION_LOST",
                11: "SSH_DISCONNECT_BY_APPLICATION",
                12: "SSH_DISCONNECT_TOO_MANY_CONNECTIONS",
                13: "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER",
                14: "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE",
                15: "SSH_DISCONNECT_ILLEGAL_USER_NAME",
            },
        ),
        PacketField("description", SSHString(), SSHString),
        PacketField("language_tag", SSHString(), SSHString),
    ]


_SSH_messages[1] = SSHDisconnect

# RFC4253 - sect 11.2


class SSHIgnore(Packet):
    fields_desc = [
        ByteEnumField("type", 2, _SSH_message_numbers),
        PacketField("data", SSHString(), SSHString),
    ]


_SSH_messages[2] = SSHIgnore

# RFC4253 - sect 11.3


class SSHServiceDebug(Packet):
    fields_desc = [
        ByteEnumField("type", 4, _SSH_message_numbers),
        YesNoByteField("always_display", 0),
        PacketField("message", SSHString(), SSHString),
        PacketField("language_tag", SSHString(), SSHString),
    ]


_SSH_messages[4] = SSHServiceDebug

# RFC4253 - sect 11.4


class SSHUnimplemented(Packet):
    fields_desc = [
        ByteEnumField("type", 3, _SSH_message_numbers),
        IntField("seq_num", 0),
    ]


_SSH_messages[3] = SSHUnimplemented

# RFC8308 - sect 2.3


class SSHExtension(Packet):
    fields_desc = [
        PacketField("extension_name", SSHString(), SSHString),
        PacketField("extension_value", SSHString(), SSHString),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


class SSHExtInfo(Packet):
    fields_desc = [
        ByteEnumField("type", 7, _SSH_message_numbers),
        FieldLenField("nr_extensions", None, length_of="extensions"),
        PacketListField("extensions", [], SSHExtension),
    ]


_SSH_messages[7] = SSHExtInfo

# RFC8308 - sect 3.2


class SSHNewCompress(Packet):
    fields_desc = [
        ByteEnumField("type", 3, _SSH_message_numbers),
    ]


_SSH_messages[8] = SSHNewCompress

# RFC8709


class SSHPublicKeyEd25519(Packet):
    fields_desc = [
        PacketField("key", SSHString(), SSHString),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


_SSH_publickeys[b"ssh-ed25519"] = SSHPublicKeyEd25519


class SSHPublicKeyEd448(Packet):
    fields_desc = [
        PacketField("key", SSHString(), SSHString),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


_SSH_publickeys[b"ssh-ed448"] = SSHPublicKeyEd448


class SSHSignatureEd25519(Packet):
    fields_desc = [
        PacketField("key", SSHString(), SSHString),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


_SSH_signatures[b"ssh-ed25519"] = SSHSignatureEd25519


class SSHSignatureEd448(Packet):
    fields_desc = [
        PacketField("key", SSHString(), SSHString),
    ]

    def default_payload_class(self, payload):
        return conf.padding_layer


_SSH_signatures[b"ssh-ed448"] = SSHSignatureEd448

bind_layers(SSH, SSH)

bind_bottom_up(TCP, SSH, sport=22)
bind_layers(TCP, SSH, dport=22)
