#!/usr/bin/env python

# http://trac.secdev.org/scapy/ticket/353

# scapy.contrib.description = IKEv2
# scapy.contrib.status = loads

from scapy.all import *
import logging


## Modified from the original ISAKMP code by Yaron Sheffer <yaronf.ietf@gmail.com>, June 2010.

import struct
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import IP,UDP
from scapy.sendrecv import sr

# see http://www.iana.org/assignments/ikev2-parameters for details
IKEv2AttributeTypes= { "Encryption":    (1, { "DES-IV64"  : 1,
                                                "DES" : 2,
                                                "3DES" : 3,
                                                "RC5" : 4,
                                                "IDEA" : 5, 
                                                "CAST" : 6, 
                                                "Blowfish" : 7, 
                                                "3IDEA" : 8,
                                                "DES-IV32" : 9,
                                                "AES-CBC" : 12,
                                                "AES-CTR" : 13,
                                                "AES-CCM-8" : 14,
                                                "AES-CCM-12" : 15,
                                                "AES-CCM-16" : 16,
                                                "AES-GCM-8ICV" : 18,
                                                "AES-GCM-12ICV" : 19,
                                                "AES-GCM-16ICV" : 20,
                                                "Camellia-CBC" : 23,
                                                "Camellia-CTR" : 24,
                                                "Camellia-CCM-8ICV" : 25,
                                                "Camellia-CCM-12ICV" : 26,
                                                "Camellia-CCM-16ICV" : 27,
                                        }, 0),
                         "PRF":            (2, {"PRF_HMAC_MD5":1,
                                                "PRF_HMAC_SHA1":2,
                                                "PRF_HMAC_TIGER":3,
                                                "PRF_AES128_XCBC":4,
                                                "PRF_HMAC_SHA2_256":5,
                                                "PRF_HMAC_SHA2_384":6,
                                                "PRF_HMAC_SHA2_512":7,
                                                "PRF_AES128_CMAC":8,
                                       }, 0),
                         "Integrity":    (3, { "HMAC-MD5-96": 1,
                                                "HMAC-SHA1-96": 2,
                                                "DES-MAC": 3,
                                                "KPDK-MD5": 4,
                                                "AES-XCBC-96": 5,
                                                "HMAC-MD5-128": 6,
                                                "HMAC-SHA1-160": 7,
                                                "AES-CMAC-96": 8,
                                                "AES-128-GMAC": 9,
                                                "AES-192-GMAC": 10,
                                                "AES-256-GMAC": 11,
                                                "SHA2-256-128": 12,
                                                "SHA2-384-192": 13,
                                                "SHA2-512-256": 14,
                                        }, 0),
                         "GroupDesc":     (4, { "768MODPgr"  : 1,
                                                "1024MODPgr" : 2, 
                                                "1536MODPgr" : 5, 
                                                "2048MODPgr" : 14, 
                                                "3072MODPgr" : 15, 
                                                "4096MODPgr" : 16, 
                                                "6144MODPgr" : 17, 
                                                "8192MODPgr" : 18, 
                                                "256randECPgr" : 19,
                                                "384randECPgr" : 20,
                                                "521randECPgr" : 21,
                                                "1024MODP160POSgr"  : 22,
                                                "2048MODP224POSgr"  : 23,
                                                "2048MODP256POSgr"  : 24,
                                                "192randECPgr" : 25,
                                                "224randECPgr" : 26,
                                        }, 0),
                         "Extended Sequence Number":       (5, {"No ESN":     0,
                                                 "ESN":   1,  }, 0),
                         }

# the name 'IKEv2TransformTypes' is actually a misnomer (since the table 
# holds info for all IKEv2 Attribute types, not just transforms, but we'll 
# keep it for backwards compatibility... for now at least
IKEv2TransformTypes = IKEv2AttributeTypes

IKEv2TransformNum = {}
for n in IKEv2TransformTypes:
    val = IKEv2TransformTypes[n]
    tmp = {}
    for e in val[1]:
        tmp[val[1][e]] = e
    IKEv2TransformNum[val[0]] = (n,tmp, val[2])

IKEv2Transforms = {}
for n in IKEv2TransformTypes:
	IKEv2Transforms[IKEv2TransformTypes[n][0]]=n

del(n)
del(e)
del(tmp)
del(val)

# Note: Transform and Proposal can only be used inside the SA payload
IKEv2_payload_type = ["None", "", "Proposal", "Transform"] 

IKEv2_payload_type.extend([""] * 29)
IKEv2_payload_type.extend(["SA","KE","IDi","IDr", "CERT","CERTREQ","AUTH","Nonce","Notify","Delete",
                       "VendorID","TSi","TSr","Encrypted","CP","EAP"])

IKEv2_exchange_type = [""] * 34
IKEv2_exchange_type.extend(["IKE_SA_INIT","IKE_AUTH","CREATE_CHILD_SA",
                        "INFORMATIONAL", "IKE_SESSION_RESUME"])


class IKEv2_class(Packet):
    def guess_payload_class(self, payload):
        np = self.next_payload
        logging.debug("For IKEv2_class np=%d" % np)
        if np == 0:
            return conf.raw_layer
        elif np < len(IKEv2_payload_type):
            pt = IKEv2_payload_type[np]
            logging.debug(globals().get("IKEv2_payload_%s" % pt, IKEv2_payload))
            return globals().get("IKEv2_payload_%s" % pt, IKEv2_payload)
        else:
            return IKEv2_payload


class IKEv2(IKEv2_class): # rfc4306
    name = "IKEv2"
    fields_desc = [
        StrFixedLenField("init_SPI","",8),
        StrFixedLenField("resp_SPI","",8),
        ByteEnumField("next_payload",0,IKEv2_payload_type),
        XByteField("version",0x20), # IKEv2, right?
        ByteEnumField("exch_type",0,IKEv2_exchange_type),
        FlagsField("flags",0, 8, ["res0","res1","res2","Initiator","Version","Response","res6","res7"]),
        IntField("id",0),
        IntField("length",None)
        ]

    def guess_payload_class(self, payload):
        if self.flags & 1:
            return conf.raw_layer
        return IKEv2_class.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, IKEv2):
            if other.init_SPI == self.init_SPI:
                return 1
        return 0
    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            p = p[:24]+struct.pack("!I",len(p))+p[28:]
        return p
       

class IKEv2_Key_Length_Attribute(IntField):
	# We only support the fixed-length Key Length attribute (the only one currently defined)
	name="key length"
	def __init__(self, name):
		IntField.__init__(self, name, "0x800E0000")
		
	def i2h(self, pkt, x):
		return IntField.i2h(self, pkt, x & 0xFFFF)
		
	def h2i(self, pkt, x):
		return IntField.h2i(self, pkt, struct.pack("!I", 0x800E0000 | int(x, 0)))


class IKEv2_Transform_ID(ShortField):
	def i2h(self, pkt, x):
		if pkt == None:
			return None
		else:
			map = IKEv2TransformNum[pkt.transform_type][1]
			return map[x]
		
	def h2i(self, pkt, x):
		if pkt == None:
			return None
		else:
			map = IKEv2TransformNum[pkt.transform_type][1]
			for k in keys(map):
				if map[k] == x:
					return k
			return None
		
class IKEv2_payload_Transform(IKEv2_class):
    name = "IKE Transform"
    fields_desc = [
        ByteEnumField("next_payload",None,{0:"last", 3:"Transform"}),
        ByteField("res",0),
        ShortField("length",8),
        ByteEnumField("transform_type",None,IKEv2Transforms),
        ByteField("res2",0),
        IKEv2_Transform_ID("transform_id", 0),
        ConditionalField(IKEv2_Key_Length_Attribute("key_length"), lambda pkt: pkt.length > 8),
    ]
            
class IKEv2_payload_Proposal(IKEv2_class):
    name = "IKEv2 Proposal"
    fields_desc = [
        ByteEnumField("next_payload",None,{0:"last", 2:"Proposal"}),
        ByteField("res",0),
        FieldLenField("length",None,"trans","H", adjust=lambda pkt,x:x+8),
        ByteField("proposal",1),
        ByteEnumField("proto",1,{1:"IKEv2"}),
        FieldLenField("SPIsize",None,"SPI","B"),
        ByteField("trans_nb",None),
        StrLenField("SPI","",length_from=lambda x:x.SPIsize),
        PacketLenField("trans",conf.raw_layer(),IKEv2_payload_Transform,length_from=lambda x:x.length-8),
        ]


class IKEv2_payload(IKEv2_class):
    name = "IKEv2 Payload"
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        FlagsField("flags",0, 8, ["critical","res1","res2","res3","res4","res5","res6","res7"]),
        FieldLenField("length",None,"load","H", adjust=lambda pkt,x:x+4),
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]


class IKEv2_payload_VendorID(IKEv2_class):
    name = "IKEv2 Vendor ID"
    overload_fields = { IKEv2: { "next_payload":43 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"vendorID","H", adjust=lambda pkt,x:x+4),
        StrLenField("vendorID","",length_from=lambda x:x.length-4),
        ]

class IKEv2_payload_Delete(IKEv2_class):
    name = "IKEv2 Vendor ID"
    overload_fields = { IKEv2: { "next_payload":42 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"vendorID","H", adjust=lambda pkt,x:x+4),
        StrLenField("vendorID","",length_from=lambda x:x.length-4),
        ]

class IKEv2_payload_SA(IKEv2_class):
    name = "IKEv2 SA"
    overload_fields = { IKEv2: { "next_payload":33 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"prop","H", adjust=lambda pkt,x:x+4),
        PacketLenField("prop",conf.raw_layer(),IKEv2_payload_Proposal,length_from=lambda x:x.length-4),
        ]

class IKEv2_payload_Nonce(IKEv2_class):
    name = "IKEv2 Nonce"
    overload_fields = { IKEv2: { "next_payload":40 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H", adjust=lambda pkt,x:x+4),
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]

class IKEv2_payload_Notify(IKEv2_class):
    name = "IKEv2 Notify"
    overload_fields = { IKEv2: { "next_payload":41 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H", adjust=lambda pkt,x:x+4),
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]

class IKEv2_payload_KE(IKEv2_class):
    name = "IKEv2 Key Exchange"
    overload_fields = { IKEv2: { "next_payload":34 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H", adjust=lambda pkt,x:x+6),
        ShortEnumField("group", 0, IKEv2TransformTypes['GroupDesc'][1]),
        StrLenField("load","",length_from=lambda x:x.length-6),
        ]

class IKEv2_payload_IDi(IKEv2_class):
    name = "IKEv2 Identification - Initiator"
    overload_fields = { IKEv2: { "next_payload":35 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+8),
        ByteEnumField("IDtype",1,{1:"IPv4_addr", 11:"Key"}),
        ByteEnumField("ProtoID",0,{0:"Unused"}),
        ShortEnumField("Port",0,{0:"Unused"}),
#        IPField("IdentData","127.0.0.1"),
        StrLenField("load","",length_from=lambda x:x.length-8),
        ]

class IKEv2_payload_IDr(IKEv2_class):
    name = "IKEv2 Identification - Responder"
    overload_fields = { IKEv2: { "next_payload":36 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+8),
        ByteEnumField("IDtype",1,{1:"IPv4_addr", 11:"Key"}),
        ByteEnumField("ProtoID",0,{0:"Unused"}),
        ShortEnumField("Port",0,{0:"Unused"}),
#        IPField("IdentData","127.0.0.1"),
        StrLenField("load","",length_from=lambda x:x.length-8),
        ]



class IKEv2_payload_Encrypted(IKEv2_class):
    name = "IKEv2 Encrypted and Authenticated"
    overload_fields = { IKEv2: { "next_payload":46 }}
    fields_desc = [
        ByteEnumField("next_payload",None,IKEv2_payload_type),
        ByteField("res",0),
        FieldLenField("length",None,"load","H",adjust=lambda pkt,x:x+4),
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]



IKEv2_payload_type_overload = {}
for i in range(len(IKEv2_payload_type)):
    name = "IKEv2_payload_%s" % IKEv2_payload_type[i]
    if name in globals():
        IKEv2_payload_type_overload[globals()[name]] = {"next_payload":i}

del(i)
del(name)
IKEv2_class.overload_fields = IKEv2_payload_type_overload.copy()

split_layers(UDP, ISAKMP, sport=500)
split_layers(UDP, ISAKMP, dport=500)

bind_layers( UDP,           IKEv2,        dport=500, sport=500) # TODO: distinguish IKEv1/IKEv2
bind_layers( UDP,           IKEv2,        dport=4500, sport=4500)

def ikev2scan(ip):
    return sr(IP(dst=ip)/UDP()/IKEv2(init_SPI=RandString(8),
                                      exch_type=34)/IKEv2_payload_SA(prop=IKEv2_payload_Proposal()))

# conf.debug_dissector = 1

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="IKEv2 alpha-level protocol implementation")
