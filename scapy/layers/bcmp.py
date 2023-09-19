import socket
import struct
import binascii

def calculate_checksum(data):
    # Part 1: Calculate Checksum
    # Convert data to bytes
    data_bytes = bytes.fromhex(data)
    
    # Calculate and return the checksum
    checksum = sum(data_bytes) & 0xFF
    return checksum

def parse_packet(packet_data):
    # Convert the hexadecimal string to bytes
    packet_bytes = bytes.fromhex(packet_data)

    # Parse Ethernet header
    eth_header = struct.unpack("!6s6sH", packet_bytes[:14])
    dest_mac = binascii.hexlify(eth_header[0]).decode("utf-8")
    src_mac = binascii.hexlify(eth_header[1]).decode("utf-8")
    eth_type = hex(eth_header[2])

    # Parse IP header (assuming Ethernet type is IPv4)
    ip_header = struct.unpack("!BBHHHBBH4s4s", packet_bytes[14:34])
    version = ip_header[0] >> 4
    ihl = ip_header[0] & 0xF
    ttl = ip_header[5]
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])

    # Print parsed information
    print("Ethernet Destination MAC:", dest_mac)
    print("Ethernet Source MAC:", src_mac)
    print("Ethernet Type:", eth_type)
    print("IP Version:", version)
    print("IP Header Length:", ihl)
    print("TTL:", ttl)
    print("Protocol:", protocol)
    print("Source IP:", src_ip)
    print("Destination IP:", dest_ip)


def extract_udp_data(packet):
    # Part 3: Extract UDP Data
    # Assuming IP protocol number for UDP is 17
    udp_header = struct.unpack("!HHHH", packet[34:42])
    src_port = udp_header[0]
    dest_port = udp_header[1]
    length = udp_header[2]
    checksum = hex(udp_header[3])

    udp_data = packet[42:]
    
    print("Source Port:", src_port)
    print("Destination Port:", dest_port)
    print("Length:", length)
    print("Checksum:", checksum)
    print("UDP Data:", binascii.hexlify(udp_data).decode("utf-8"))

def parse_icmp_packet(packet):
    # Part 4: Parse ICMP Packet
    icmp_header = struct.unpack("!BBH", packet[34:38])
    icmp_type = icmp_header[0]
    code = icmp_header[1]
    checksum = hex(icmp_header[2])
    
    icmp_data = packet[38:]

    print("ICMP Type:", icmp_type)
    print("Code:", code)
    print("Checksum:", checksum)
    print("ICMP Data:", binascii.hexlify(icmp_data).decode("utf-8"))

def parse_tcp_packet(packet):
    # Part 5: Parse TCP Packet
    tcp_header = struct.unpack("!HHLLBBHHH", packet[34:54])
    src_port = tcp_header[0]
    dest_port = tcp_header[1]
    sequence_num = tcp_header[2]
    ack_num = tcp_header[3]
    data_offset = (tcp_header[4] >> 4) * 4
    flags = bin(tcp_header[5])
    window = tcp_header[6]
    checksum = hex(tcp_header[7])
    urgent_ptr = tcp_header[8]
    
    tcp_data = packet[34 + data_offset:]

    print("Source Port:", src_port)
    print("Destination Port:", dest_port)
    print("Sequence Number:", sequence_num)
    print("Acknowledgment Number:", ack_num)
    print("Data Offset:", data_offset)
    print("Flags:", flags)
    print("Window:", window)
    print("Checksum:", checksum)
    print("Urgent Pointer:", urgent_ptr)
    print("TCP Data:", binascii.hexlify(tcp_data).decode("utf-8"))

def parse_igmp_packet(packet):
    # Part 6: Parse IGMP Packet
    igmp_header = struct.unpack("!BBH4s", packet[34:42])
    igmp_type = igmp_header[0]
    max_resp_time = igmp_header[1]
    checksum = hex(igmp_header[2])
    group_address = socket.inet_ntoa(igmp_header[3])
    
    igmp_data = packet[42:]

    print("IGMP Type:", igmp_type)
    print("Max Resp Time:", max_resp_time)
    print("Checksum:", checksum)
    print("Group Address:", group_address)
    print("IGMP Data:", binascii.hexlify(igmp_data).decode("utf-8"))

def parse_ospf_packet(packet):
    # Part 7: Parse OSPF Packet
    ospf_header = struct.unpack("!BBH4s4s4sI", packet[34:58])
    version = ospf_header[0]
    ospf_type = ospf_header[1]
    packet_length = ospf_header[2]
    router_id = socket.inet_ntoa(ospf_header[3])
    area_id = socket.inet_ntoa(ospf_header[4])
    checksum = hex(ospf_header[5])
    auth_type = ospf_header[6]
    
    ospf_data = packet[58:]

    print("OSPF Version:", version)
    print("OSPF Type:", ospf_type)
    print("Packet Length:", packet_length)
    print("Router ID:", router_id)
    print("Area ID:", area_id)
    print("Checksum:", checksum)
    print("Authentication Type:", auth_type)
    print("OSPF Data:", binascii.hexlify(ospf_data).decode("utf-8"))

def parse_bgp_packet(packet):
    # Part 8: Parse BGP Packet
    bgp_header = struct.unpack("!H", packet[34:36])
    bgp_type = bgp_header[0]

    bgp_data = packet[36:]

    print("BGP Type:", bgp_type)
    print("BGP Data:", binascii.hexlify(bgp_data).decode("utf-8"))

def parse_pim_packet(packet):
    # Part 9: Parse PIM Packet
    pim_header = struct.unpack("!BBH4s4s", packet[34:52])
    pim_type = pim_header[0]
    reserved = pim_header[1]
    checksum = hex(pim_header[2])
    unicast_rp = socket.inet_ntoa(pim_header[3])
    multicast_group = socket.inet_ntoa(pim_header[4])
    
    pim_data = packet[52:]

    print("PIM Type:", pim_type)
    print("Reserved:", reserved)
    print("Checksum:", checksum)
    print("Unicast RP:", unicast_rp)
    print("Multicast Group:", multicast_group)
    print("PIM Data:", binascii.hexlify(pim_data).decode("utf-8"))

def parse_eigrp_packet(packet):
    # Part 10: Parse EIGRP Packet
    eigrp_header = struct.unpack("!HHBBH4sH", packet[34:48])
    version = eigrp_header[0]
    opcode = eigrp_header[1]
    checksum = hex(eigrp_header[4])
    source_ip = socket.inet_ntoa(eigrp_header[5])
    
    eigrp_data = packet[48:]

    print("EIGRP Version:", version)
    print("EIGRP Opcode:", opcode)
    print("Checksum:", checksum)
    print("Source IP:", source_ip)
    print("EIGRP Data:", binascii.hexlify(eigrp_data).decode("utf-8"))

def parse_rip_packet(packet):
    # Part 11: Parse RIP Packet
    rip_header = struct.unpack("!BBH", packet[34:38])
    command = rip_header[0]
    version = rip_header[1]
    checksum = hex(rip_header[2])
    
    rip_data = packet[38:]

    print("RIP Command:", command)
    print("RIP Version:", version)
    print("Checksum:", checksum)
    print("RIP Data:", binascii.hexlify(rip_data).decode("utf-8"))

def parse_803ah_efm_data(packet, bcmp_params, code, data_s):
    # Part 13: Parse 803ah EFM Data
    index = 0
    params_s = 1024

    if code == 0x0:
        for index in range(data_s):
            if index == 0:
                bcmp_params += " -local_info_tlv "
            if index == 16:
                bcmp_params += " -remote_info_tlv "
            if index == 32:
                bcmp_params += " -info_tlv_3 "
            
            temp_efm = packet[index]
            bcmp_params += "{temp_efm:02x}"
    
    # Continue with other conditions for code values...

def main():
    # Main code to use the defined functions

    # Example Packet Data (hexadecimal)
    # Full packet data including Ethernet and IP headers
    packet_data = "ffffffffffff00123456789abcdef01234508004500002800010000400656d9c0a80101c0a80102"
    checksum = calculate_checksum(packet_data)
    print("Checksum:", checksum)

    parse_packet(packet_data)
    extract_udp_data(packet_data)
    parse_icmp_packet(packet_data)
    parse_tcp_packet(packet_data)
    parse_igmp_packet(packet_data)
    parse_ospf_packet(packet_data)
    parse_bgp_packet(packet_data)
    parse_pim_packet(packet_data)
    parse_eigrp_packet(packet_data)
    parse_rip_packet(packet_data)

    # Example 803ah EFM Data
    efm_packet = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
    bcmp_params = ""
    parse_803ah_efm_data(efm_packet, bcmp_params, 0x0, len(efm_packet))
    print("BCMP Params:", bcmp_params)

if __name__ == "__main__":
    main()
