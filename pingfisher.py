import socket
import struct
import time
from sys import exit
debug = 0

def debug_print(*msg):
	if debug:
		for data in msg:
			print(data)
			
def parse_ipv4_address(ip_address):
	return ".".join(map(str , ip_address))

icmp_counter = 0
ping_counter = 0
sock = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(3))
while True:
	try:
		ethernet_frame , addr = sock.recvfrom(2048)
		if ethernet_frame:
			debug_print("\n\n\n\n[+]Received Ethernet frame")
			debug_print("Printing raw frame data:" , ethernet_frame)
			destination_mac , source_mac , protocol = struct.unpack("! 6s 6s H" , ethernet_frame[:14])
			debug_print("[+]Source mac:" , source_mac)
			debug_print("[+]Destination mac:" , destination_mac)
			debug_print("[+]Protocol:" , socket.htons(protocol))

			#check if the packet is IPv4 packet
			if socket.htons(protocol) == 8:
				debug_print("[+]Detected IPv4 packet")
				ipv4_packet = ethernet_frame[14:]
				version_header_length = ipv4_packet[0]
				header_length = (version_header_length & 15) * 4
				ttl , packet_protocol , source_ip , destination_ip = struct.unpack("! 8x B B 2x 4s 4s" , ipv4_packet[:20])
				debug_print("Protocol inside IPv4:" , packet_protocol)
				
				#check if the protocol field inside IPv4 packet is ICMP
				if packet_protocol == 1:
					if ipv4_packet[header_length] == 8:
						print("Ping [REQUEST] from {}".format(parse_ipv4_address(source_ip)))
					elif ipv4_packet[header_length] == 0:
						debug_print("Ping [REPLY] from {}".format(parse_ipv4_address(source_ip)))
					ping_counter = ping_counter + 1
						

	except KeyboardInterrupt:
		print("\n[+]Received {} packets".format(ping_counter))
		exit(0)
