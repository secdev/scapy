#! /usr/bin/env python

# scapy.contrib.description = Skinny Call Control Protocol (SCCP)
# scapy.contrib.status = loads


#############################################################################
#                                                                           #
#  scapy-skinny.py --- Skinny Call Control Protocol (SCCP) extension        #
#                                                                           #
#  Copyright (C) 2006    Nicolas Bareil      <nicolas.bareil@ eads.net>     #
#                        EADS/CRC security team                             #
#                                                                           #
#  This file is part of Scapy                                               #
#  Scapy is free software: you can redistribute it and/or modify            #
#  under the terms of the GNU General Public License version 2 as           #
#  published by the Free Software Foundation; version 2.                    #
#                                                                           #
#  This program is distributed in the hope that it will be useful, but      #
#  WITHOUT ANY WARRANTY; without even the implied warranty of               #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU        #
#  General Public License for more details.                                 #
#                                                                           #
#############################################################################

from __future__ import absolute_import
import time
import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import FlagsField, IPField, LEIntEnumField, LEIntField, \
    StrFixedLenField
from scapy.layers.inet import TCP
from scapy.modules.six.moves import range
from scapy.volatile import RandShort
from scapy.config import conf

#####################################################################
# Helpers and constants
#####################################################################

skinny_messages_cls = {
    # Station -> Callmanager
    0x0000: "SkinnyMessageKeepAlive",
    0x0001: "SkinnyMessageRegister",
    0x0002: "SkinnyMessageIpPort",
    0x0003: "SkinnyMessageKeypadButton",
    0x0004: "SkinnyMessageEnblocCall",
    0x0005: "SkinnyMessageStimulus",
    0x0006: "SkinnyMessageOffHook",
    0x0007: "SkinnyMessageOnHook",
    0x0008: "SkinnyMessageHookFlash",
    0x0009: "SkinnyMessageForwardStatReq",
    0x000A: "SkinnyMessageSpeedDialStatReq",
    0x000B: "SkinnyMessageLineStatReq",
    0x000C: "SkinnyMessageConfigStatReq",
    0x000D: "SkinnyMessageTimeDateReq",
    0x000E: "SkinnyMessageButtonTemplateReq",
    0x000F: "SkinnyMessageVersionReq",
    0x0010: "SkinnyMessageCapabilitiesRes",
    0x0011: "SkinnyMessageMediaPortList",
    0x0012: "SkinnyMessageServerReq",
    0x0020: "SkinnyMessageAlarm",
    0x0021: "SkinnyMessageMulticastMediaReceptionAck",
    0x0022: "SkinnyMessageOpenReceiveChannelAck",
    0x0023: "SkinnyMessageConnectionStatisticsRes",
    0x0024: "SkinnyMessageOffHookWithCgpn",
    0x0025: "SkinnyMessageSoftKeySetReq",
    0x0026: "SkinnyMessageSoftKeyEvent",
    0x0027: "SkinnyMessageUnregister",
    0x0028: "SkinnyMessageSoftKeyTemplateReq",
    0x0029: "SkinnyMessageRegisterTokenReq",
    0x002A: "SkinnyMessageMediaTransmissionFailure",
    0x002B: "SkinnyMessageHeadsetStatus",
    0x002C: "SkinnyMessageMediaResourceNotification",
    0x002D: "SkinnyMessageRegisterAvailableLines",
    0x002E: "SkinnyMessageDeviceToUserData",
    0x002F: "SkinnyMessageDeviceToUserDataResponse",
    0x0030: "SkinnyMessageUpdateCapabilities",
    0x0031: "SkinnyMessageOpenMultiMediaReceiveChannelAck",
    0x0032: "SkinnyMessageClearConference",
    0x0033: "SkinnyMessageServiceURLStatReq",
    0x0034: "SkinnyMessageFeatureStatReq",
    0x0035: "SkinnyMessageCreateConferenceRes",
    0x0036: "SkinnyMessageDeleteConferenceRes",
    0x0037: "SkinnyMessageModifyConferenceRes",
    0x0038: "SkinnyMessageAddParticipantRes",
    0x0039: "SkinnyMessageAuditConferenceRes",
    0x0040: "SkinnyMessageAuditParticipantRes",
    0x0041: "SkinnyMessageDeviceToUserDataVersion1",
    # Callmanager -> Station */
    0x0081: "SkinnyMessageRegisterAck",
    0x0082: "SkinnyMessageStartTone",
    0x0083: "SkinnyMessageStopTone",
    0x0085: "SkinnyMessageSetRinger",
    0x0086: "SkinnyMessageSetLamp",
    0x0087: "SkinnyMessageSetHkFDetect",
    0x0088: "SkinnyMessageSpeakerMode",
    0x0089: "SkinnyMessageSetMicroMode",
    0x008A: "SkinnyMessageStartMediaTransmission",
    0x008B: "SkinnyMessageStopMediaTransmission",
    0x008C: "SkinnyMessageStartMediaReception",
    0x008D: "SkinnyMessageStopMediaReception",
    0x008F: "SkinnyMessageCallInfo",
    0x0090: "SkinnyMessageForwardStat",
    0x0091: "SkinnyMessageSpeedDialStat",
    0x0092: "SkinnyMessageLineStat",
    0x0093: "SkinnyMessageConfigStat",
    0x0094: "SkinnyMessageTimeDate",
    0x0095: "SkinnyMessageStartSessionTransmission",
    0x0096: "SkinnyMessageStopSessionTransmission",
    0x0097: "SkinnyMessageButtonTemplate",
    0x0098: "SkinnyMessageVersion",
    0x0099: "SkinnyMessageDisplayText",
    0x009A: "SkinnyMessageClearDisplay",
    0x009B: "SkinnyMessageCapabilitiesReq",
    0x009C: "SkinnyMessageEnunciatorCommand",
    0x009D: "SkinnyMessageRegisterReject",
    0x009E: "SkinnyMessageServerRes",
    0x009F: "SkinnyMessageReset",
    0x0100: "SkinnyMessageKeepAliveAck",
    0x0101: "SkinnyMessageStartMulticastMediaReception",
    0x0102: "SkinnyMessageStartMulticastMediaTransmission",
    0x0103: "SkinnyMessageStopMulticastMediaReception",
    0x0104: "SkinnyMessageStopMulticastMediaTransmission",
    0x0105: "SkinnyMessageOpenReceiveChannel",
    0x0106: "SkinnyMessageCloseReceiveChannel",
    0x0107: "SkinnyMessageConnectionStatisticsReq",
    0x0108: "SkinnyMessageSoftKeyTemplateRes",
    0x0109: "SkinnyMessageSoftKeySetRes",
    0x0110: "SkinnyMessageStationSelectSoftKeysMessage",
    0x0111: "SkinnyMessageCallState",
    0x0112: "SkinnyMessagePromptStatus",
    0x0113: "SkinnyMessageClearPromptStatus",
    0x0114: "SkinnyMessageDisplayNotify",
    0x0115: "SkinnyMessageClearNotify",
    0x0116: "SkinnyMessageCallPlane",
    0x0117: "SkinnyMessageCallPlane",
    0x0118: "SkinnyMessageUnregisterAck",
    0x0119: "SkinnyMessageBackSpaceReq",
    0x011A: "SkinnyMessageRegisterTokenAck",
    0x011B: "SkinnyMessageRegisterTokenReject",
    0x0042: "SkinnyMessageDeviceToUserDataResponseVersion1",
    0x011C: "SkinnyMessageStartMediaFailureDetection",
    0x011D: "SkinnyMessageDialedNumber",
    0x011E: "SkinnyMessageUserToDeviceData",
    0x011F: "SkinnyMessageFeatureStat",
    0x0120: "SkinnyMessageDisplayPriNotify",
    0x0121: "SkinnyMessageClearPriNotify",
    0x0122: "SkinnyMessageStartAnnouncement",
    0x0123: "SkinnyMessageStopAnnouncement",
    0x0124: "SkinnyMessageAnnouncementFinish",
    0x0127: "SkinnyMessageNotifyDtmfTone",
    0x0128: "SkinnyMessageSendDtmfTone",
    0x0129: "SkinnyMessageSubscribeDtmfPayloadReq",
    0x012A: "SkinnyMessageSubscribeDtmfPayloadRes",
    0x012B: "SkinnyMessageSubscribeDtmfPayloadErr",
    0x012C: "SkinnyMessageUnSubscribeDtmfPayloadReq",
    0x012D: "SkinnyMessageUnSubscribeDtmfPayloadRes",
    0x012E: "SkinnyMessageUnSubscribeDtmfPayloadErr",
    0x012F: "SkinnyMessageServiceURLStat",
    0x0130: "SkinnyMessageCallSelectStat",
    0x0131: "SkinnyMessageOpenMultiMediaChannel",
    0x0132: "SkinnyMessageStartMultiMediaTransmission",
    0x0133: "SkinnyMessageStopMultiMediaTransmission",
    0x0134: "SkinnyMessageMiscellaneousCommand",
    0x0135: "SkinnyMessageFlowControlCommand",
    0x0136: "SkinnyMessageCloseMultiMediaReceiveChannel",
    0x0137: "SkinnyMessageCreateConferenceReq",
    0x0138: "SkinnyMessageDeleteConferenceReq",
    0x0139: "SkinnyMessageModifyConferenceReq",
    0x013A: "SkinnyMessageAddParticipantReq",
    0x013B: "SkinnyMessageDropParticipantReq",
    0x013C: "SkinnyMessageAuditConferenceReq",
    0x013D: "SkinnyMessageAuditParticipantReq",
    0x013F: "SkinnyMessageUserToDeviceDataVersion1",
}

skinny_callstates = {
    0x1: "Off Hook",
    0x2: "On Hook",
    0x3: "Ring out",
    0xc: "Proceeding",
}


skinny_ring_type = {
    0x1: "Ring off"
}

skinny_speaker_modes = {
    0x1: "Speaker on",
    0x2: "Speaker off"
}

skinny_lamp_mode = {
    0x1: "Off (?)",
    0x2: "On",
}

skinny_stimulus = {
    0x9: "Line"
}


############
#  Fields  #
############

class SkinnyDateTimeField(StrFixedLenField):
    def __init__(self, name, default):
        StrFixedLenField.__init__(self, name, default, 32)

    def m2i(self, pkt, s):
        year, month, dow, day, hour, min, sec, millisecond = struct.unpack('<8I', s)  # noqa: E501
        return (year, month, day, hour, min, sec)

    def i2m(self, pkt, val):
        if isinstance(val, str):
            val = self.h2i(pkt, val)
        tmp_lst = val[:2] + (0,) + val[2:7] + (0,)
        return struct.pack('<8I', *tmp_lst)

    def i2h(self, pkt, x):
        if isinstance(x, str):
            return x
        else:
            return time.ctime(time.mktime(x + (0, 0, 0)))

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)

    def h2i(self, pkt, s):
        t = ()
        if isinstance(s, str):
            t = time.strptime(s)
            t = t[:2] + t[2:-3]
        else:
            if not s:
                y, m, d, h, min, sec, rest, rest, rest = time.gmtime(time.time())  # noqa: E501
                t = (y, m, d, h, min, sec)
            else:
                t = s
        return t


###########################
#  Packet abstract class  #
###########################

class SkinnyMessageGeneric(Packet):
    name = 'Generic message'


class SkinnyMessageKeepAlive(Packet):
    name = 'keep alive'


class SkinnyMessageKeepAliveAck(Packet):
    name = 'keep alive ack'


class SkinnyMessageOffHook(Packet):
    name = 'Off Hook'
    fields_desc = [LEIntField("unknown1", 0),
                   LEIntField("unknown2", 0), ]


class SkinnyMessageOnHook(SkinnyMessageOffHook):
    name = 'On Hook'


class SkinnyMessageCallState(Packet):
    name = 'Skinny Call state message'
    fields_desc = [LEIntEnumField("state", 1, skinny_callstates),
                   LEIntField("instance", 1),
                   LEIntField("callid", 0),
                   LEIntField("unknown1", 4),
                   LEIntField("unknown2", 0),
                   LEIntField("unknown3", 0)]


class SkinnyMessageSoftKeyEvent(Packet):
    name = 'Soft Key Event'
    fields_desc = [LEIntField("key", 0),
                   LEIntField("instance", 1),
                   LEIntField("callid", 0)]


class SkinnyMessageSetRinger(Packet):
    name = 'Ring message'
    fields_desc = [LEIntEnumField("ring", 0x1, skinny_ring_type),
                   LEIntField("unknown1", 0),
                   LEIntField("unknown2", 0),
                   LEIntField("unknown3", 0)]


_skinny_tones = {
    0x21: 'Inside dial tone',
    0x22: 'xxx',
    0x23: 'xxx',
    0x24: 'Alerting tone',
    0x25: 'Reorder Tone'
}


class SkinnyMessageStartTone(Packet):
    name = 'Start tone'
    fields_desc = [LEIntEnumField("tone", 0x21, _skinny_tones),
                   LEIntField("unknown1", 0),
                   LEIntField("instance", 1),
                   LEIntField("callid", 0)]


class SkinnyMessageStopTone(SkinnyMessageGeneric):
    name = 'stop tone'
    fields_desc = [LEIntField("instance", 1),
                   LEIntField("callid", 0)]


class SkinnyMessageSpeakerMode(Packet):
    name = 'Speaker mdoe'
    fields_desc = [LEIntEnumField("ring", 0x1, skinny_speaker_modes)]


class SkinnyMessageSetLamp(Packet):
    name = 'Lamp message (light of the phone)'
    fields_desc = [LEIntEnumField("stimulus", 0x5, skinny_stimulus),
                   LEIntField("instance", 1),
                   LEIntEnumField("mode", 2, skinny_lamp_mode)]


class SkinnyMessageStationSelectSoftKeysMessage(Packet):
    name = 'Station Select Soft Keys Message'
    fields_desc = [LEIntField("instance", 1),
                   LEIntField("callid", 0),
                   LEIntField("set", 0),
                   LEIntField("map", 0xffff)]


class SkinnyMessagePromptStatus(Packet):
    name = 'Prompt status'
    fields_desc = [LEIntField("timeout", 0),
                   StrFixedLenField("text", b"\0" * 32, 32),
                   LEIntField("instance", 1),
                   LEIntField("callid", 0)]


class SkinnyMessageCallPlane(Packet):
    name = 'Activate/Deactivate Call Plane Message'
    fields_desc = [LEIntField("instance", 1)]


class SkinnyMessageTimeDate(Packet):
    name = 'Setting date and time'
    fields_desc = [SkinnyDateTimeField("settime", None),
                   LEIntField("timestamp", 0)]


class SkinnyMessageClearPromptStatus(Packet):
    name = 'clear prompt status'
    fields_desc = [LEIntField("instance", 1),
                   LEIntField("callid", 0)]


class SkinnyMessageKeypadButton(Packet):
    name = 'keypad button'
    fields_desc = [LEIntField("key", 0),
                   LEIntField("instance", 1),
                   LEIntField("callid", 0)]


class SkinnyMessageDialedNumber(Packet):
    name = 'dialed number'
    fields_desc = [StrFixedLenField("number", "1337", 24),
                   LEIntField("instance", 1),
                   LEIntField("callid", 0)]


_skinny_message_callinfo_restrictions = ['CallerName', 'CallerNumber', 'CalledName', 'CalledNumber', 'OriginalCalledName', 'OriginalCalledNumber', 'LastRedirectName', 'LastRedirectNumber'] + ['Bit%d' % i for i in range(8, 15)]  # noqa: E501


class SkinnyMessageCallInfo(Packet):
    name = 'call information'
    fields_desc = [StrFixedLenField("callername", "Jean Valjean", 40),
                   StrFixedLenField("callernum", "1337", 24),
                   StrFixedLenField("calledname", "Causette", 40),
                   StrFixedLenField("callednum", "1034", 24),
                   LEIntField("lineinstance", 1),
                   LEIntField("callid", 0),
                   StrFixedLenField("originalcalledname", "Causette", 40),
                   StrFixedLenField("originalcallednum", "1034", 24),
                   StrFixedLenField("lastredirectingname", "Causette", 40),
                   StrFixedLenField("lastredirectingnum", "1034", 24),
                   LEIntField("originalredirectreason", 0),
                   LEIntField("lastredirectreason", 0),
                   StrFixedLenField('voicemailboxG', b'\0' * 24, 24),
                   StrFixedLenField('voicemailboxD', b'\0' * 24, 24),
                   StrFixedLenField('originalvoicemailboxD', b'\0' * 24, 24),
                   StrFixedLenField('lastvoicemailboxD', b'\0' * 24, 24),
                   LEIntField('security', 0),
                   FlagsField('restriction', 0, 16, _skinny_message_callinfo_restrictions),  # noqa: E501
                   LEIntField('unknown', 0)]


class SkinnyRateField(LEIntField):
    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        return '%d ms/pkt' % x


_skinny_codecs = {
    0x0: 'xxx',
    0x1: 'xxx',
    0x2: 'xxx',
    0x3: 'xxx',
    0x4: 'G711 ulaw 64k'
}

_skinny_echo = {
    0x0: 'echo cancellation off',
    0x1: 'echo cancellation on'
}


class SkinnyMessageOpenReceiveChannel(Packet):
    name = 'open receive channel'
    fields_desc = [LEIntField('conference', 0),
                   LEIntField('passthru', 0),
                   SkinnyRateField('rate', 20),
                   LEIntEnumField('codec', 4, _skinny_codecs),
                   LEIntEnumField('echo', 0, _skinny_echo),
                   LEIntField('unknown1', 0),
                   LEIntField('callid', 0)]

    def guess_payload_class(self, p):
        return conf.padding_layer


_skinny_receive_channel_status = {
    0x0: 'ok',
    0x1: 'ko'
}


class SkinnyMessageOpenReceiveChannelAck(Packet):
    name = 'open receive channel'
    fields_desc = [LEIntEnumField('status', 0, _skinny_receive_channel_status),
                   IPField('remote', '0.0.0.0'),
                   LEIntField('port', RandShort()),
                   LEIntField('passthru', 0),
                   LEIntField('callid', 0)]


_skinny_silence = {
    0x0: 'silence suppression off',
    0x1: 'silence suppression on',
}


class SkinnyFramePerPacketField(LEIntField):
    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        return '%d frames/pkt' % x


class SkinnyMessageStartMediaTransmission(Packet):
    name = 'start multimedia transmission'
    fields_desc = [LEIntField('conference', 0),
                   LEIntField('passthru', 0),
                   IPField('remote', '0.0.0.0'),
                   LEIntField('port', RandShort()),
                   SkinnyRateField('rate', 20),
                   LEIntEnumField('codec', 4, _skinny_codecs),
                   LEIntField('precedence', 200),
                   LEIntEnumField('silence', 0, _skinny_silence),
                   SkinnyFramePerPacketField('maxframes', 0),
                   LEIntField('unknown1', 0),
                   LEIntField('callid', 0)]

    def guess_payload_class(self, p):
        return conf.padding_layer


class SkinnyMessageCloseReceiveChannel(Packet):
    name = 'close receive channel'
    fields_desc = [LEIntField('conference', 0),
                   LEIntField('passthru', 0),
                   IPField('remote', '0.0.0.0'),
                   LEIntField('port', RandShort()),
                   SkinnyRateField('rate', 20),
                   LEIntEnumField('codec', 4, _skinny_codecs),
                   LEIntField('precedence', 200),
                   LEIntEnumField('silence', 0, _skinny_silence),
                   LEIntField('callid', 0)]


class SkinnyMessageStopMultiMediaTransmission(Packet):
    name = 'stop multimedia transmission'
    fields_desc = [LEIntField('conference', 0),
                   LEIntField('passthru', 0),
                   LEIntField('callid', 0)]


class Skinny(Packet):
    name = "Skinny"
    fields_desc = [LEIntField("len", None),
                   LEIntField("res", 0),
                   LEIntEnumField("msg", 0, skinny_messages_cls)]

    def post_build(self, pkt, p):
        if self.len is None:
            # on compte pas les headers len et reserved
            tmp_len = len(p) + len(pkt) - 8
            pkt = struct.pack('@I', tmp_len) + pkt[4:]
        return pkt + p

# An helper


def get_cls(name, fallback_cls):
    return globals().get(name, fallback_cls)
    # return __builtin__.__dict__.get(name, fallback_cls)


for msgid, strcls in skinny_messages_cls.items():
    cls = get_cls(strcls, SkinnyMessageGeneric)
    bind_layers(Skinny, cls, {"msg": msgid})

bind_layers(TCP, Skinny, {"dport": 2000})
bind_layers(TCP, Skinny, {"sport": 2000})

if __name__ == "__main__":
    from scapy.main import interact
    interact(mydict=globals(), mybanner="Welcome to Skinny add-on")
