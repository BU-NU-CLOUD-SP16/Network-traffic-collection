from struct import pack, unpack
from http import extract_http
import socket

# checksum functions needed for calculation checksum
"""
def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
        # print 'i: '+ str(i)
    return ~s & 0xffff
"""


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        # w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        w = (ord(msg[i]) << 8) + ord(msg[i+1])
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


fpcap = open('now.pcap', 'rb')
text = fpcap.read()
index = 0

pcap_file_header_fmt = ['majic', 'version_major', 'version_minor', 'zone', 'max_len', 'time_stap', 'link_type']

pcap_header_fmt = ['gmt_time', 'micro_time', 'pcap_len', 'len']

ip_header_fmt = ['version,ihl', 'tos', 'tot_len', 'id', 'frag_off', 'ttl', 'protocol', 'check', 'saddr', 'daddr']

tcp_header_fmt = ['src_port', 'dst_port', 'seq_no', 'ack_no', 'tcp_offset_res', 'tcp_flags', 'window', 'cksum', 'urg_pt']

# pcap file head
global_head = unpack('IHHIIII', text[index:24 + index])
index += 24
global_head_dict = dict(zip(pcap_file_header_fmt, global_head))
print global_head_dict


while index < len(text):
    # packet_head
    packet_head = unpack('IIII', text[index:16 + index])
    pcap_head_dict = dict(zip(pcap_header_fmt, packet_head))
    index += 16
    pcap_len = pcap_head_dict['pcap_len']

    # skb is all the packet data
    skb = text[index: pcap_len + index]

    # mac head
    # print_mac_head(skb[:14])

    # ip head
    ip_head = unpack('!BBHHHBBHII', skb[14:34])
    ip_head_dict = dict(zip(ip_header_fmt, ip_head))
    ip_head_length = (ip_head_dict['version,ihl'] & 0xF) * 4

    # filter tcp head
    ports = unpack('!HH', skb[14+ip_head_length:14+ip_head_length+4])
    if ports[0] == 80 or ports[1] == 80:
        tcp_head = unpack('!HHLLBBHHH', skb[14+ip_head_length:14+ip_head_length+20])
        tcp_head_dict = dict(zip(tcp_header_fmt, tcp_head))
        offset = tcp_head_dict['tcp_offset_res']
        tcp_head_length = 4*(offset >> 4)

        # pseudo header fields
        source_address = ip_head_dict['saddr']
        dest_address = ip_head_dict['daddr']
        placeholder = 0
        protocol = ip_head_dict['protocol']
        tcp_length = pcap_len-34
        psh = pack('!IIBBH', ip_head_dict['saddr'],
                   ip_head_dict['daddr'], placeholder, protocol, tcp_length)
        # cksum_msg = psh +
        #     skb[14+ip_head_length: 14+ip_head_length+16] + pack('!H', 0) + skb[14+ip_head_length+18:pcap_len]
        cksum_msg = psh + skb[14+ip_head_length: pcap_len]
        if len(cksum_msg) % 2 == 1:
            cksum_msg += pack('!B', 0)

        # a = tcp_head_dict['cksum']
        # print a
        # print ((a & 0xff00) >> 8) + ((a & 0x00ff) << 8)
        if checksum(cksum_msg) != 0:
            continue

        dict_field = {'Timestamp': None, 'sIP': None, 'sPort': None, 'dIP': None, 'dPort': None,
                      'Domain': None, 'URL': None,'user_agent': None, 'referer': None,
                      'result_code': None, 'action': None, 'bytes': None, 'content-type': None}

        dict_field['Timestamp'] = pcap_head_dict['gmt_time']
        dict_field['sIP'] = socket.inet_ntoa(pack('!I', ip_head_dict['saddr']))
        dict_field['dIP'] = socket.inet_ntoa(pack('!I', ip_head_dict['daddr']))
        dict_field['sPort'] = tcp_head_dict['src_port']
        dict_field['dPort'] = tcp_head_dict['dst_port']
        dict_field['bytes'] = pcap_len - 14 - ip_head_length - tcp_head_length
        if pcap_len > 14+ip_head_length+tcp_head_length:
            data = skb[14+ip_head_length+tcp_head_length: pcap_len]
            if data.find('HTTP', 0, data.find('\r\n')) != -1:
                extract_http(data, dict_field)
                # all the needed fields are in dict_field
                print dict_field

    index += pcap_len
