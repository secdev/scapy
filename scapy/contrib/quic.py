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
    #     fields_desc = [ BitField("Header Form", size=1,default=1), # default=1 because in long header packet, this field is set to 1.
    #                     BitField("Fixed Bit", size=1),
    #                     BitField("Long Packet Type", size=2),
    #                     BitField("Type-Specific Bits",size=4),  
    #                     BitField("Version", size=32),
    #                     BitField("Destination Connection ID Length",size=8),
    #                     BitExtendedField("Destination Connection ID",None,1), # extension_bit=1 . more bytes following this field
    #                     BitField("Source Connection ID Length",size=8),
    #                     BitExtendedField("Source Connection ID",1) # extension_bit=1 . no bytes following this field.
    #                     #payload attached from here.                        
    #                 ]
        
    #     def optional_field(field):

    #         if field=="Reserved Bits":
    #             fields_desc.append(BitField("Reserved Bits", size=2))
            
    #         elif field=="Packet Number Length":
    #             fields_desc.append(BitField("Packet Number Length", size=2))
            
    #         # length of Packet Number and Payload in bytes
    #         elif field=="Length":
    #             fields_desc.append(BitExtendedField("Length"))

    #         elif field=="Packet Number":
    #             fields_desc.append(BitExtendedField("Packet Number"))
    


# long header packets
class VersionNegotiationPacket(Packet):

    # version negotiation packet header
    fields_desc = [ BitField("Header Form", size=1,default=1), # default=1 because in long header packet, this field is set to 1.
                    BitField("Unused", size=7),
                    BitField("Version", size=32,default=0),
                    BitField("Destination Connection ID Length",size=8),
                    BitExtendedField("Destination Connection ID",None,1), # extension_bit=1 . more bytes following this field
                    
                    BoundStrLenField(name="Destination Connection ID"),
                    
                    BitField("Source Connection ID Length"),
                    BitExtendedField("Source Connection ID",1), # extension_bit=1 . no bytes following this field.
                    BitField("Supported Version",size=32),
                    #payload attached from here.                        
                ]

class InitialPacket(Packet):     
    
    # initial packet header
    fields_desc = [ BitField("Header Form", size=1,default=1), # default=1 because in long header packet, this field is set to 1.
                    BitField("Fixed Bit", size=1,default=1),
                    BitField("Long Packet Type", size=2,default=0),
                    BitField("Reserved Bits", size=2),
                    BitField("Packet Number Length", size=2),
                    BitField("Version", size=32),
                    BitField("Destination Connection ID Length",size=8),
                    BitExtendedField("Destination Connection ID",None,1), 
                    BitField("Source Connection ID Length",size=8),
                    BitExtendedField("Source Connection ID",1),
                    BitExtendedField("Token Length",default=0),
                    BitExtendedField("Token"),
                    BitExtendedField("Length"),
                    BitExtendedField("Packet Number"),
                    #payload attached from here.                        
                ]

    
class _0RTTPacket(Packet):
    
    # 0-RTT Packet Header
    fields_desc = [ BitField("Header Form", size=1,default=1),
                    BitField("Fixed Bit", size=1,default=1),
                    BitField("Long Packet Type", size=2,default=1),
                    BitField("Reserved Bits", size=2),
                    BitField("Packet Number Length", size=2),
                    BitField("Version", size=32),
                    BitField("Destination Connection ID Length",size=8),
                    BitExtendedField("Destination Connection ID",None,1), 
                    BitField("Source Connection ID Length",size=8),
                    BitExtendedField("Source Connection ID",1),
                    BitExtendedField("Length"),
                    BitExtendedField("Packet Number"),
                    #payload attached from here.                        
                ]

class HandshakePacket(Packet):

    # Handshake Packet Header
    fields_desc = [ BitField("Header Form", size=1,default=1),
                    BitField("Fixed Bit", size=1,default=1),
                    BitField("Long Packet Type", size=2,default=2),
                    BitField("Reserved Bits", size=2),
                    BitField("Packet Number Length", size=2),
                    BitField("Version", size=32),
                    BitField("Destination Connection ID Length",size=8),
                    BitExtendedField("Destination Connection ID",None,1), 
                    BitField("Source Connection ID Length",size=8),
                    BitExtendedField("Source Connection ID",1),
                    BitExtendedField("Length"),
                    BitExtendedField("Packet Number"),
                    #payload attached from here.                        
                ]
        

class RetryPacket():
        
    fields_desc = [ BitField("Header Form", size=1,default=1),
                    BitField("Fixed Bit", size=1,default=1),
                    BitField("Long Packet Type", size=2,default=3),
                    BitField("Reserved Bits", size=2),
                    BitField("Unused", size=4),
                    BitField("Version", size=32),
                    BitField("Destination Connection ID Length",size=8),
                    BitExtendedField("Destination Connection ID",None,1), 
                    BitField("Source Connection ID Length",size=8),
                    BitExtendedField("Retry Token"),
                    BitField("Source Connection ID Length",size=128)
                    #payload attached from here.                        
                ]

# short header packet
class _1RTTPacket():
    fields_desc = [ BitField("Header Form", size=1,default=0),
                    BitField("Fixed Bit", size=1,default=1),
                    BitField("Spin Bit",size=1),
                    BitField("Reserved Bit",size=2),
                    BitField("Key Phase",size=1),
                    BitField("Packet Number Length",size=2),
                    BitExtendedField("Destination Connection ID",None,1),
                    BitExtendedField("Packet Number",None,1),
                    #payload attached from here.                        
                ]