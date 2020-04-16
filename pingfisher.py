import socket
import struct
import time

debug = 0

def debug_print(*msg):
	if debug:
		for data in msg:
			print(data)
			
def parse_ip(ip_address):
	return ".".join(map(str , ip_address))

icmp_counter = 0
sock = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(3))
while True:
	ethernet_frame , addr = sock.recvfrom(2048)
	if ethernet_frame:
		debug_print("\n\n\n\n[+]Received Ethernet frame")
		debug_print("Printing raw frame data:" , ethernet_frame)
		destination_mac , source_mac , protocol = struct.unpack("! 6s 6s H" , ethernet_frame[:14])
		debug_print("[+]Source mac:" , source_mac)
		debug_print("[+]Destination mac:" , destination_mac)
		debug_print("[+]Protocol:" , socket.htons(protocol))

		if socket.htons(protocol) == 8:
			debug_print("[+]Detected IPv4 packet")
			ipv4_packet = ethernet_frame[14:]
			ttl , packet_protocol , source_ip , destination_ip = struct.unpack("! 8x B B 2x 4s 4s" , ipv4_packet[:20])
			debug_print("Protocol inside IPv4:" , packet_protocol)
			if packet_protocol == 1:
				icmp_counter = (icmp_counter + 1) % 4
				if icmp_counter == 0:
					print("Ping received from" , parse_ip(source_ip))
