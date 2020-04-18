import socket
import struct
import time
from sys import exit
import ipaddress
debug = 0

def debug_print(*msg):
	if debug:
		for data in msg:
			print(data)
			
def parse_ipv4_address(ip_address):
	return ".".join(map(str , ip_address))

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
					#check if the ICMP packet is a ping request or ping response
					if ipv4_packet[header_length] == 8:
						print("Ping \033[93m[REQUEST]\033[00m from {}".format(parse_ipv4_address(source_ip)))
					elif ipv4_packet[header_length] == 0:
						print("Ping \033[95m[RESPONSE]\033[00m from {}".format(parse_ipv4_address(source_ip)))
					ping_counter = ping_counter + 1
				
			#check if the packet is IPv6 packet			
			elif socket.htons(protocol) == 56710:
				print("[+]Detected IPv6 packet")
				ipv6_paket = ethernet_frame[14:]
				version_class_flowLabel , payload_length , next_header , hop_limit , source_ipv6 , destination_ipv6 = struct.unpack("! 4s H B B 16s 16s" , ipv6_paket[:40])
				debug_print("Payload_length: " , payload_length)
				debug_print("Next_header: " , next_header)
				debug_print("Hop_limit: " , hop_limit)
				debug_print("Source IPv6: " , ipaddress.IPv6Address(source_ipv6))
				debug_print("Destination IPv6: " , ipaddress.IPv6Address(destination_ipv6))
				
				#check if it's an ICMPv6 packet
				if next_header == 58:
					print("Ping received from {}".format(ipaddress.IPv6Address(destination_ipv6)))
					

	except KeyboardInterrupt:
		print("\n[+]Received {} packets".format(ping_counter))
		exit(0)
