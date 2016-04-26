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

def CreateBatch(file):
	Array = []
	fpcap = open(file, 'rb')
	text = fpcap.read()
	index = 0
	count = 0
	pcap_header_fmt = ['gmt_time', 'micro_time', 'pcap_len', 'len']
	ip_header_fmt = ['version,ihl', 'tos', 'tot_len', 'id', 'frag_off', 'ttl', 'protocol', 'check', 'saddr', 'daddr']
	tcp_header_fmt = ['src_port', 'dst_port', 'seq_no', 'ack_no', 'tcp_offset_res', 'tcp_flags', 'window', 'cksum', 'urg_pt']

	# pcap file head
	global_head = unpack('IHHIIII', text[index:24 + index])
	index += 24

	while index < len(text):
		packet_head = unpack('IIII', text[index:16 + index])
		pcap_head_dict = dict(zip(pcap_header_fmt, packet_head))
		index += 16
		pcap_len = pcap_head_dict['pcap_len']
		# skb is all the packet data
		skb = text[index: pcap_len + index]

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
			placeholder = 0
			protocol = ip_head_dict['protocol']
			tcp_length = pcap_len-34
			psh = pack('!IIBBH', ip_head_dict['saddr'],
			ip_head_dict['daddr'], placeholder, protocol, tcp_length)
			# skb[14+ip_head_length: 14+ip_head_length+16] + pack('!H', 0) + skb[14+ip_head_length+18:pcap_len]
			cksum_msg = psh + skb[14+ip_head_length: pcap_len]
			if len(cksum_msg) % 2 == 1:
				cksum_msg += pack('!B', 0)
				#if checksum(cksum_msg) == 0: #FOR NOW
					#continue
			dict_field = {
			"measurement":"http",
			"tags":{
				'sIP': socket.inet_ntoa(pack('!I', ip_head_dict['saddr'])),
				'sPort': tcp_head_dict['src_port'],
				'dIP': socket.inet_ntoa(pack('!I', ip_head_dict['daddr'])),
				'dPort': tcp_head_dict['dst_port'],
				'Domain': None,
				'URL': None,
				'user_agent': None,
				'referer': None,
				'result_code': None,
				'action': None,
				'bytes': pcap_len - 14 - ip_head_length - tcp_head_length,
				'content-type': None
			},
			'time': None,
			"fields":{
				"value":12.0
			}
			}
			# time now in micro seconds for accuracy
			dict_field['time'] = int(pcap_head_dict['gmt_time'])*1000000 + int(pcap_head_dict['micro_time'])
			if pcap_len > 14+ip_head_length+tcp_head_length:
				data = skb[14+ip_head_length+tcp_head_length: pcap_len]
				checker = data.find('\r\n')
				if(checker != -1):
					# ADJUSTED TO FIX LOGICAL ERROR THAT MADE DB WRITE ERRORS
					checker2 = data.find('HTTP', 0, checker)
					if checker2 != -1:
						extract_http(data, dict_field)
						Array.append(dict_field)
						count+=1
		index += pcap_len
	return Array
