from struct import pack, unpack
from http import extract_http
import socket
from influxdb import InfluxDBClient
import time
import datetime
from threading import Thread
import threading
import fileinput
import sys

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


#def grep():
#	print("THE FILE BEING READ: {}\n".format(fileinput.filename()))
#	text = ''
#	for line in fileinput.input():
#		text += line
#	return text
#print(grep())


def CreateBatch():
	Array = []
	client = InfluxDBClient(host='127.0.0.1', port=8086, database='TRAFFIC')
	# fpcap = open(file, 'rb')
	# text = fpcap.read()
	#regexp = re.compile(sys.argv[1])
	#text = fileinput.input(sys.argv[2:])
	count = 0
	pcap_file_header_fmt = ['majic', 'version_major', 'version_minor', 'zone', 'max_len', 'time_stap', 'link_type']

	pcap_header_fmt = ['gmt_time', 'micro_time', 'pcap_len', 'len']

	ip_header_fmt = ['version,ihl', 'tos', 'tot_len', 'id', 'frag_off', 'ttl', 'protocol', 'check', 'saddr', 'daddr']

	tcp_header_fmt = ['src_port', 'dst_port', 'seq_no', 'ack_no', 'tcp_offset_res', 'tcp_flags', 'window', 'cksum', 'urg_pt']

        text = sys.stdin.read(24)
	# pcap file head
	global_head = unpack('IHHIIII', text[:24])
	global_head_dict = dict(zip(pcap_file_header_fmt, global_head))

	while True:
                text = sys.stdin.read(16)
		packet_head = unpack('IIII', text[:16])
    		pcap_head_dict = dict(zip(pcap_header_fmt, packet_head))

    		pcap_len = pcap_head_dict['pcap_len']

    		# skb is all the packet data
                text = sys.stdin.read(pcap_len)
    		skb = text[: pcap_len]

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
        		# if checksum(cksum_msg) != 0:
            			# continue

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
        		if pcap_len >= 14+ip_head_length+tcp_head_length:
            			data = skb[14+ip_head_length+tcp_head_length: pcap_len]
            			if data.find('HTTP', 0, data.find('\r\n')) != -1:
                			extract_http(data, dict_field)
                			# all the needed fields are in dict_field
                			count+=1
					Array.append(dict_field)
					if count%1000 == 0:
						print "count: " + str(count)
						client.write_points(Array)
						print "writing to db..."
						Array = []


def execute(db):
	print("THIS IS DB: {}\n".format(db))
	t0 = time.time()
	count, v = CreateBatch()
	t1 = time.time()
	reading = t1-t0
	rate1 = float(count)/reading
	print("TIME READING: {} SPEED PER REQUEST: {}\n".format(reading,rate1))
	
	if db == '1':
		print("ENTERED 1")
		client = InfluxDBClient(host='127.0.0.1', port=8086, database='newDB')
		t2 = time.time()
		client.write_points(v)
		t3 = time.time()
		influx = t3-t2
		rate2 = float(count)/influx
		print("TIME INFLUX: {} SPEED PER REQUEST: {}\n\n".format(influx,rate2))
	if db == '2':
		print("ENTERED TWO")
		client = InfluxDBClient(host='127.0.0.1', port=8086, database='DB2')
		t2 = time.time()
		client.write_points(v)
		t3 = time.time()
		influx = t3-t2
		rate2 = float(count)/influx
		print("TIME INFLUX: {} SPEED PER REQUEST: {}\n\n".format(influx,rate2))

""""	
array = ['1','2']
for x in range(0,len(array)):
	str = '/home/ubuntu/xxx{}.pcap'.format(array[x])
	thread = Thread(target = execute, args = (str,array[x], ))
	thread.start()
thread.start()
print x

#print(array)

"""""


CreateBatch()
# execute(1)
