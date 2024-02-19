import socket
import struct
import textwrap 


TAB_1 = "\t - "
TAB_2 = "\t\t - "
TAB_3 = "\t\t\t - "
TAB_4 = "\t\t\t\t - "

DATA_TAB_1 = "\t "
DATA_TAB_2 = "\t\t "
DATA_TAB_3 = "\t\t\t "
DATA_TAB_4 = "\t\t\t\t "


#Capturing the Traffic
def main():
    #socket.ntohs(3) is for making sure that the byte order is correct so we can read it 
    #SOCK_RAW and AF_PACKET check the pdf resource file to understand what is it  
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    #This loop for listening for any data that come across
    while True:
        #The recvfrom method in the socket module helps us to receive all the data (0 and 1) from the socket and store it in raw_data and addr variables 
        #The parameter passed is the buffer size; 65565 is the maximum buffer size  
        raw_data, addr = conn.recvfrom(65536)   

        #Extract all 0 and 1 from raw_data and store it in these variables
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print(TAB_1 + "Destination MAC Address: {}, Source MAC Address: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))

        #Value of 8 for IPv4 (check this if you want to understand why 8 "https://en.wikipedia.org/wiki/EtherType")
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            #To understand what is 1/6/17 check the "IP-Header.pdf" file.
            #Check ICMP:
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            #Check TCP:
            elif proto == 6: 
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + "Flags:")
                print(TAB_3 + 'URG: {}, ACK {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, (data)))

            #Check UDP:
            elif proto == 17:
                src_port, dest_port, length, data = udp_packet(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port:, Length {}'.format(src_port, dest_port, length))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))

        else:
            print('Data:')
            print(format_multi_line(DATA_TAB_1, data))



                    


#Unpacks Ethernet Frame
def ethernet_frame(data):
    #We capture the data and unpack the first 14 bytes because we know the first 14 bytes will give us the destination, the source and also the type(Ethernet protocol)
    #'!'    : Interpret data in network byte order.
    #'6s'   : Read 6 bytes as a string (destination MAC address).
    #'6s'   : Read another 6 bytes as a string (source MAC address).
    #'H'    : Read 2 bytes as an unsigned short (Ethernet protocol field).
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14]) 

    #socket.htons(proto) is for taking the bytes and make them readable, get_mac_addr() function is for making src_mac and dest_mac readable too
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:] 


#Returns properly formated MAC address (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    #First we convert the bytes_addr to a proper string format (hexadecimal)
    bytes_addr = map('{:02x}'.format, bytes_addr)  #If you didn't understand this command, check the explanation file
    
    #Format the bytes_addr array to be like a properly MAC address  
    mac_addr = ':'.join(bytes_addr).upper() 
    return mac_addr


#Unpacks IPv4 Packet Headers
def ipv4_packet(data):
    #Note to undersant what these lines of code u must open "IP-Header.pdf" file
    #This code is extracting the version and header length information from the first byte of an IPv4 packet's header.
    #If you didn't understand these lignes, check the explanation file
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    #'!'    : Indicates that the data should be interpreted in network byte order (big-endian).
    #'8x'   : Skips 8 bytes in the data. This is often used to skip fields in the header that are not of interest.
    #'B B'  : Reads two bytes, each representing an unsigned byte (8 bits). These correspond to the "Time to Live" (TTL) and "Protocol" fields in the IPv4 header.
    #'2x'   : Skips 2 bytes in the data
    #'4s 4s': Reads two sets of 4 bytes each as strings. These correspond to the source and destination IP addresses in the IPv4 header.
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    #Note that the actual data begins from the header length to the end.
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


#Returns properly formated IPv4 address 
def ipv4(addr):
    #First we convert the addr array to a proper string format 
    address = map(str, addr)  
    #Format the addr string to be like a properly IPv4 address  
    IP = '.'.join(address)
    return IP

#Unpacks ICMP packet
def icmp_packet(data):
    #Check the "ICMP Header*.png" pictures to understand why we choose "data[:4]".
    icmp_type, code, checksum = struct.unpack('! B B H',data[:4])
    return icmp_type, code, checksum, data[4:]

#Unpacks TCP segment
def tcp_segment(data):
    #Check the "TCP-IP Packet.jpg" picture to understand these lignes of code.

    #'H' : Source Port (2 bytes = 16 bits) 
    #'H' : Destination Port (2 bytes = 16 bits )
    #'L' : Sequence Number (4 bytes = 32 bits)
    #'L' : Acknowledgement Number (4 bytes = 32 bits)
    #'H' : Offset and Reserved Flags (2 bytes = 16 bits)
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    
    #If you didn't understand this ligne, check the explanation file
    offset = (offset_reserved_flags >> 12) * 4 #offset is the header length of the TCP segment
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_packet(data):
    #Check the "udp-packet.png" picture to understand these lignes of code.
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]


#Formats multi-line data (chatgpt helped me with this code)
def format_multi_line(prefix, string, size=20):
    if isinstance(string, bytes):
        lines = []
        for i in range(0, len(string), size):
            chunk = string[i:i + size]
            hex_part = ' '.join(f'{byte:02x}' for byte in chunk)
            text_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
            lines.append(f"{prefix} {hex_part.ljust(size * 3)}  {text_part}")
        return '\n'.join(lines)
    
    #The overall purpose of this function is to format byte data in a way that resembles the output of 
    #a typical TCP stream in tools like Wireshark or Burp Suite. It displays both the hexadecimal and 
    #ASCII representations of the byte data in a structured and aligned manner. Adjusting the size 
    #parameter allows you to control the length of each line.

main()



