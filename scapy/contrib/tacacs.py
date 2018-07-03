# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) 2017 Francois Contat <francois.contat@ssi.gouv.fr>

# Based on tacacs+ v6 draft https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-06  # noqa: E501

# scapy.contrib.description = Terminal Access Controller Access-Control System+
# scapy.contrib.status = loads

import struct
import hashlib

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, IntField
from scapy.fields import FieldListField
from scapy.fields import FieldLenField, ConditionalField, StrLenField
from scapy.layers.inet import TCP
from scapy.compat import chb, orb
from scapy.config import conf
from scapy.modules.six.moves import range

SECRET = 'test'


def obfuscate(pay, secret, session_id, version, seq):
    '''

    Obfuscation methodology from section 3.7
    https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-06#section-3.7

    '''

    pad = b""
    curr_pad = b""

    # pad length must equal the payload to obfuscate.
    # pad = {MD5_1 [,MD5_2 [ ... ,MD5_n]]}

    while len(pad) < len(pay):

        msg = hashlib.md5()
        msg.update(struct.pack('!I', session_id))
        msg.update(secret.encode())
        msg.update(struct.pack('!BB', version, seq))
        msg.update(curr_pad)
        curr_pad = msg.digest()
        pad += curr_pad

    # Obf/Unobfuscation via XOR operation between plaintext and pad

    return b"".join(chb(orb(pad[i]) ^ orb(pay[i])) for i in range(len(pay)))


TACACSPRIVLEVEL = {15: 'Root',
                   1: 'User',
                   0: 'Minimum'}

##########################
# Authentication Packets #
##########################

TACACSVERSION = {1: 'Tacacs',
                 192: 'Tacacs+'}

TACACSTYPE = {1: 'Authentication',
              2: 'Authorization',
              3: 'Accounting'}

TACACSFLAGS = {1: 'Unencrypted',
               4: 'Single Connection'}

TACACSAUTHENACTION = {1: 'Login',
                      2: 'Change Pass',
                      4: 'Send Authentication'}

TACACSAUTHENTYPE = {1: 'ASCII',
                    2: 'PAP',
                    3: 'CHAP',
                    4: 'ARAP',  # Deprecated
                    5: 'MSCHAP',
                    6: 'MSCHAPv2'}

TACACSAUTHENSERVICE = {0: 'None',
                       1: 'Login',
                       2: 'Enable',
                       3: 'PPP',
                       4: 'ARAP',
                       5: 'PT',
                       6: 'RCMD',
                       7: 'X25',
                       8: 'NASI',
                       9: 'FwProxy'}

TACACSREPLYPASS = {1: 'PASS',
                   2: 'FAIL',
                   3: 'GETDATA',
                   4: 'GETUSER',
                   5: 'GETPASS',
                   6: 'RESTART',
                   7: 'ERROR',
                   21: 'FOLLOW'}

TACACSREPLYFLAGS = {1: 'NOECHO'}

TACACSCONTINUEFLAGS = {1: 'ABORT'}


class TacacsAuthenticationStart(Packet):

    '''

    Tacacs authentication start body from section 4.1
    https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-06#section-4.1

    '''

    name = 'Tacacs Authentication Start Body'
    fields_desc = [ByteEnumField('action', 1, TACACSAUTHENACTION),
                   ByteEnumField('priv_lvl', 1, TACACSPRIVLEVEL),
                   ByteEnumField('authen_type', 1, TACACSAUTHENTYPE),
                   ByteEnumField('authen_service', 1, TACACSAUTHENSERVICE),
                   FieldLenField('user_len', None, fmt='!B', length_of='user'),
                   FieldLenField('port_len', None, fmt='!B', length_of='port'),
                   FieldLenField('rem_addr_len', None, fmt='!B', length_of='rem_addr'),  # noqa: E501
                   FieldLenField('data_len', None, fmt='!B', length_of='data'),
                   ConditionalField(StrLenField('user', '', length_from=lambda x: x.user_len),  # noqa: E501
                                    lambda x: x != ''),
                   StrLenField('port', '', length_from=lambda x: x.port_len),
                   StrLenField('rem_addr', '', length_from=lambda x: x.rem_addr_len),  # noqa: E501
                   StrLenField('data', '', length_from=lambda x: x.data_len)]


class TacacsAuthenticationReply(Packet):

    '''

    Tacacs authentication reply body from section 4.2
    https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-06#section-4.2

    '''

    name = 'Tacacs Authentication Reply Body'
    fields_desc = [ByteEnumField('status', 1, TACACSREPLYPASS),
                   ByteEnumField('flags', 0, TACACSREPLYFLAGS),
                   FieldLenField('server_msg_len', None, fmt='!H', length_of='server_msg'),  # noqa: E501
                   FieldLenField('data_len', None, fmt='!H', length_of='data'),
                   StrLenField('server_msg', '', length_from=lambda x: x.server_msg_len),  # noqa: E501
                   StrLenField('data', '', length_from=lambda x: x.data_len)]


class TacacsAuthenticationContinue(Packet):

    '''

    Tacacs authentication continue body from section 4.3
    https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-06#section-4.3

    '''

    name = 'Tacacs Authentication Continue Body'
    fields_desc = [FieldLenField('user_msg_len', None, fmt='!H', length_of='user_msg'),  # noqa: E501
                   FieldLenField('data_len', None, fmt='!H', length_of='data'),
                   ByteEnumField('flags', 1, TACACSCONTINUEFLAGS),
                   StrLenField('user_msg', '', length_from=lambda x: x.user_msg_len),  # noqa: E501
                   StrLenField('data', '', length_from=lambda x: x.data_len)]

#########################
# Authorization Packets #
#########################


TACACSAUTHORTYPE = {0: 'Not Set',
                    1: 'None',
                    2: 'Kerberos 5',
                    3: 'Line',
                    4: 'Enable',
                    5: 'Local',
                    6: 'Tacacs+',
                    8: 'Guest',
                    16: 'Radius',
                    17: 'Kerberos 4',
                    32: 'RCMD'}

TACACSAUTHORSTATUS = {1: 'Pass Add',
                      2: 'Pass repl',
                      16: 'Fail',
                      17: 'Error',
                      33: 'Follow'}


class TacacsAuthorizationRequest(Packet):

    '''

    Tacacs authorization request body from section 5.1
    https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-06#section-5.1

    '''

    name = 'Tacacs Authorization Request Body'
    fields_desc = [ByteEnumField('authen_method', 0, TACACSAUTHORTYPE),
                   ByteEnumField('priv_lvl', 1, TACACSPRIVLEVEL),
                   ByteEnumField('authen_type', 1, TACACSAUTHENTYPE),
                   ByteEnumField('authen_service', 1, TACACSAUTHENSERVICE),
                   FieldLenField('user_len', None, fmt='!B', length_of='user'),
                   FieldLenField('port_len', None, fmt='!B', length_of='port'),
                   FieldLenField('rem_addr_len', None, fmt='!B', length_of='rem_addr'),  # noqa: E501
                   FieldLenField('arg_cnt', None, fmt='!B', count_of='arg_len_list'),  # noqa: E501
                   FieldListField('arg_len_list', [], ByteField('', 0),
                                  length_from=lambda pkt: pkt.arg_cnt),
                   StrLenField('user', '', length_from=lambda x: x.user_len),
                   StrLenField('port', '', length_from=lambda x: x.port_len),
                   StrLenField('rem_addr', '', length_from=lambda x: x.rem_addr_len)]  # noqa: E501

    def guess_payload_class(self, pay):
        if self.arg_cnt > 0:
            return TacacsPacketArguments
        return conf.padding_layer


class TacacsAuthorizationReply(Packet):

    '''

    Tacacs authorization reply body from section 5.2
    https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-06#section-5.2

    '''

    name = 'Tacacs Authorization Reply Body'
    fields_desc = [ByteEnumField('status', 0, TACACSAUTHORSTATUS),
                   FieldLenField('arg_cnt', None, fmt='!B', count_of='arg_len_list'),  # noqa: E501
                   FieldLenField('server_msg_len', None, fmt='!H', length_of='server_msg'),  # noqa: E501
                   FieldLenField('data_len', None, fmt='!H', length_of='data'),
                   FieldListField('arg_len_list', [], ByteField('', 0),
                                  length_from=lambda pkt: pkt.arg_cnt),
                   StrLenField('server_msg', '', length_from=lambda x: x.server_msg_len),  # noqa: E501
                   StrLenField('data', '', length_from=lambda x: x.data_len)]

    def guess_payload_class(self, pay):
        if self.arg_cnt > 0:
            return TacacsPacketArguments
        return conf.padding_layer


######################
# Accounting Packets #
######################

TACACSACNTFLAGS = {2: 'Start',
                   4: 'Stop',
                   8: 'Watchdog'}

TACACSACNTSTATUS = {1: 'Success',
                    2: 'Error',
                    33: 'Follow'}


class TacacsAccountingRequest(Packet):

    '''

    Tacacs accounting request body from section 6.1
    https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-06#section-6.1

    '''

    name = 'Tacacs Accounting Request Body'
    fields_desc = [ByteEnumField('flags', 0, TACACSACNTFLAGS),
                   ByteEnumField('authen_method', 0, TACACSAUTHORTYPE),
                   ByteEnumField('priv_lvl', 1, TACACSPRIVLEVEL),
                   ByteEnumField('authen_type', 1, TACACSAUTHENTYPE),
                   ByteEnumField('authen_service', 1, TACACSAUTHENSERVICE),
                   FieldLenField('user_len', None, fmt='!B', length_of='user'),
                   FieldLenField('port_len', None, fmt='!B', length_of='port'),
                   FieldLenField('rem_addr_len', None, fmt='!B', length_of='rem_addr'),  # noqa: E501
                   FieldLenField('arg_cnt', None, fmt='!B', count_of='arg_len_list'),  # noqa: E501
                   FieldListField('arg_len_list', [], ByteField('', 0),
                                  length_from=lambda pkt: pkt.arg_cnt),
                   StrLenField('user', '', length_from=lambda x: x.user_len),
                   StrLenField('port', '', length_from=lambda x: x.port_len),
                   StrLenField('rem_addr', '', length_from=lambda x: x.rem_addr_len)]  # noqa: E501

    def guess_payload_class(self, pay):
        if self.arg_cnt > 0:
            return TacacsPacketArguments
        return conf.padding_layer


class TacacsAccountingReply(Packet):

    '''

    Tacacs accounting reply body from section 6.2
    https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-06#section-6.2

    '''

    name = 'Tacacs Accounting Reply Body'
    fields_desc = [FieldLenField('server_msg_len', None, fmt='!H', length_of='server_msg'),  # noqa: E501
                   FieldLenField('data_len', None, fmt='!H', length_of='data'),
                   ByteEnumField('status', None, TACACSACNTSTATUS),
                   StrLenField('server_msg', '', length_from=lambda x: x.server_msg_len),  # noqa: E501
                   StrLenField('data', '', length_from=lambda x: x.data_len)]


class TacacsPacketArguments(Packet):

    '''

    Class defined to handle the arguments listed at the end of tacacs+
    Authorization and Accounting packets.

    '''

    __slots__ = ['_len']
    name = 'Arguments in Tacacs+ packet'
    fields_desc = [StrLenField('data', '', length_from=lambda pkt: pkt._len)]

    def pre_dissect(self, s):
        cur = self.underlayer
        i = 0

        # Searching the position in layer in order to get its length

        while isinstance(cur, TacacsPacketArguments):
            cur = cur.underlayer
            i += 1
        self._len = cur.arg_len_list[i]
        return s

    def guess_payload_class(self, pay):
        cur = self.underlayer
        i = 0

        # Guessing if Argument packet. Nothing in encapsulated via tacacs+

        while isinstance(cur, TacacsPacketArguments):
            cur = cur.underlayer
            i += 1
        if i + 1 < cur.arg_cnt:
            return TacacsPacketArguments
        return conf.padding_layer


class TacacsClientPacket(Packet):

    '''

    Super class for tacacs packet in order to get them unencrypted
    Obfuscation methodology from section 3.7
    https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-06#section-3.7

    '''

    def post_dissect(self, pay):

        if self.flags == 0:
            pay = obfuscate(pay, SECRET, self.session_id, self.version, self.seq)  # noqa: E501
            return pay


class TacacsHeader(TacacsClientPacket):

    '''

    Tacacs Header packet from section 3.8
    https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-06#section-3.8

    '''

    name = 'Tacacs Header'
    fields_desc = [ByteEnumField('version', 192, TACACSVERSION),
                   ByteEnumField('type', 1, TACACSTYPE),
                   ByteField('seq', 1),
                   ByteEnumField('flags', 0, TACACSFLAGS),
                   IntField('session_id', 0),
                   IntField('length', None)]

    def guess_payload_class(self, payload):

        # Guessing packet type from type and seq values

        # Authentication packet - type 1

        if self.type == 1:
            if self.seq % 2 == 0:
                return TacacsAuthenticationReply
            if sum(struct.unpack('bbbb', payload[4:8])) == len(payload[8:]):
                return TacacsAuthenticationStart
            elif sum(struct.unpack('!hh', payload[:4])) == len(payload[5:]):
                return TacacsAuthenticationContinue

        # Authorization packet - type 2

        if self.type == 2:
            if self.seq % 2 == 0:
                return TacacsAuthorizationReply
            return TacacsAuthorizationRequest

        # Accounting packet - type 3

        if self.type == 3:
            if self.seq % 2 == 0:
                return TacacsAccountingReply
            return TacacsAccountingRequest

        return conf.raw_layer

    def post_build(self, p, pay):

        # Setting length of packet to obfuscate if not filled by user

        if self.length is None and pay:
            p = p[:-4] + struct.pack('!I', len(pay))

        if self.flags == 0:

            pay = obfuscate(pay, SECRET, self.session_id, self.version, self.seq)  # noqa: E501
            return p + pay

        return p

    def hashret(self):
        return struct.pack('I', self.session_id)

    def answers(self, other):
        return (isinstance(other, TacacsHeader) and
                self.seq == other.seq + 1 and
                self.type == other.type and
                self.session_id == other.session_id)


bind_layers(TCP, TacacsHeader, dport=49)
bind_layers(TCP, TacacsHeader, sport=49)
bind_layers(TacacsHeader, TacacsAuthenticationStart, type=1, dport=49)
bind_layers(TacacsHeader, TacacsAuthenticationReply, type=1, sport=49)

if __name__ == '__main__':
    from scapy.main import interact
    interact(mydict=globals(), mybanner='tacacs+')
