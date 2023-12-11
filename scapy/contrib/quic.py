"""
Support QUIC Protocol

[RFC 9000]
"""


from scapy.fields import BitField,BitExtendedField,BoundStrLenField
from scapy.packet import Packet

class QUIC(Packet):
    name="QUIC"
    # All numeric values are encoded in network byte order (that is, big endian), and all field sizes are in bits. 
    # Hexadecimal notation is used for describing the value of fields.
    # https://datatracker.ietf.org/doc/html/rfc9000#section-17-1
    # Default is big endian encoding in scapy. QUIC also uses big endian. Therefore, default scapy field encodings are used

    # def long_header_packet():
    #     # long header packet header
    #     fields_desc = [ BitField("headerform", size=1,default=1), # default=1 because in long header packet, this field is set to 1.
    #                     BitField("fixedbit", size=1),
    #                     BitField("longpackettype", size=2),
    #                     BitField("typespecificbits",size=4),  
    #                     BitField("version", size=32),
    #                     BitField("dconnectionidlen",size=8),
    #                     BitExtendedField("dconnectionid",None,1), # extension_bit=1 . more bytes following this field
    #                     BitField("sconnectionidlen",size=8),
    #                     BitExtendedField("sconnectionid",1) # extension_bit=1 . no bytes following this field.
    #                     #payload attached from here.                        
    #                 ]
        
    #     def optional_field(field):

    #         if field=="reservedbits":
    #             fields_desc.append(BitField("reservedbits", size=2))
            
    #         elif field=="packetnumberlength":
    #             fields_desc.append(BitField("packetnumberlength", size=2))
            
    #         # length of packetnum and Payload in bytes
    #         elif field=="Length":
    #             fields_desc.append(BitExtendedField("length"))

    #         elif field=="packetnum":
    #             fields_desc.append(BitExtendedField("packetnum"))



# long header packets
class VersionNegotiationPacket(Packet):

    # version negotiation packet header
    fields_desc = [ BitField("headerform", size=1,default=1), # default=1 because in long header packet, this field is set to 1.
                    BitField("unused", size=7),
                    BitField("version", size=32,default=0),
                    BitField("dconnectionidlen",size=8),
                    BitExtendedField("dconnectionid",None,1), # extension_bit=1 . more bytes following this field
                    BitField("sconnectionidlen"),
                    BitExtendedField("sconnectionid",1), # extension_bit=1 . no bytes following this field.
                    BitField("supportedversion",size=32),
                    #payload attached from here.                        
                ]

class InitialPacket(Packet):     
    
    # initial packet header
    fields_desc = [ BitField("headerform", size=1,default=1), # default=1 because in long header packet, this field is set to 1.
                    BitField("fixedbit", size=1,default=1),
                    BitField("longpackettype", size=2,default=0),
                    BitField("reservedbits", size=2),
                    BitField("packetnumberlength", size=2),
                    BitField("version", size=32),
                    BitField("dconnectionidlen",size=8),
                    BitExtendedField("dconnectionid",None,1), 
                    BitField("sconnectionidlen",size=8),
                    BitExtendedField("sconnectionid",1),
                    BitExtendedField("tokenlength",default=0),
                    BitExtendedField("token"),
                    BitExtendedField("length"),
                    BitExtendedField("packetnum"),
                    #payload attached from here.                        
                ]

    
class _0RTTPacket(Packet):
    
    # 0-RTT Packet Header
    fields_desc = [ BitField("headerform", size=1,default=1),
                    BitField("fixedbit", size=1,default=1),
                    BitField("longpackettype", size=2,default=1),
                    BitField("reservedbits", size=2),
                    BitField("packetnumberlength", size=2),
                    BitField("version", size=32),
                    BitField("dconnectionidlen",size=8),
                    BitExtendedField("dconnectionid",None,1), 
                    BitField("sconnectionidlen",size=8),
                    BitExtendedField("sconnectionid",1),
                    BitExtendedField("length"),
                    BitExtendedField("packetnum"),
                    #payload attached from here.                        
                ]

class HandshakePacket(Packet):

    # Handshake Packet Header
    fields_desc = [ BitField("headerform", size=1,default=1),
                    BitField("fixedbit", size=1,default=1),
                    BitField("longpackettype", size=2,default=2),
                    BitField("reservedbits", size=2),
                    BitField("packetnumberlength", size=2),
                    BitField("version", size=32),
                    BitField("dconnectionidlen",size=8),
                    BitExtendedField("dconnectionid",None,1), 
                    BitField("sconnectionidlen",size=8),
                    BitExtendedField("sconnectionid",1),
                    BitExtendedField("length"),
                    BitExtendedField("packetnum"),
                    #payload attached from here.                        
                ]
        

class RetryPacket():
        
    fields_desc = [ BitField("headerform", size=1,default=1),
                    BitField("fixedbit", size=1,default=1),
                    BitField("longpackettype", size=2,default=3),
                    BitField("reservedbits", size=2),
                    BitField("Unused", size=4),
                    BitField("Version", size=32),
                    BitField("dconnectionidlen",size=8),
                    BitExtendedField("dconnectionid",None,1), 
                    BitField("sconnectionidlen",size=8),
                    BitExtendedField("retrytoken"),
                    BitField("sconnectionidlen",size=128)
                    #payload attached from here.                        
                ]

# short header packet
class _1RTTPacket():
    fields_desc = [ BitField("headerform", size=1,default=0),
                    BitField("fixedbit", size=1,default=1),
                    BitField("spinbit",size=1),
                    BitField("reservedbit",size=2),
                    BitField("keyphase",size=1),
                    BitField("packetnumberlength",size=2),
                    BitExtendedField("dconnectionid",None,1),
                    BitExtendedField("packetnum",None,1),
                    #payload attached from here.                        
                ]