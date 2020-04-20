import socket
from struct import unpack
from sys import exit
from ipaddress import IPv4Address , IPv6Address
from argparse import ArgumentParser

PACKET_TAB = "\t"

#parse command line arguments
parser = ArgumentParser(description="")
parser.add_argument("--debug" , "-d" , help="Debug mode" , action = "store_true" , default = False)
arguments = parser.parse_args()

#function to print the debug information only when the debug flag is set
def debug_print(*msg):
	if arguments.debug:
		for data in msg:
			print(data , end = " ")
		print()
		
def parse_mac_address(mac_byte):
	mac_bytes_string = map('{:02x}'.format, mac_byte)
	mac_address = ':'.join(mac_bytes_string).upper()
	return mac_address

def print_ethernet_frame_info(destination_mac , source_mac , protocol):
	debug_print("\033[91m====================================================\033[00m")
	debug_print("[+]Received Ethernet frame")
	debug_print("[+]Source mac:" , parse_mac_address(source_mac))
	debug_print("[+]Destination mac:" , parse_mac_address(destination_mac))
	debug_print("[+]Protocol:" , socket.htons(protocol))

def print_ipv4_packet_info(header_length , ttl , packet_protocol , source_ip , destination_ip):
	debug_print("\033[34m++++++++++++++++++++++++++++++++++++++++++++++++++++\033[00m")
	debug_print(PACKET_TAB + "[+]Detected IPv4 packet")
	debug_print(PACKET_TAB + "[+]Header Length:" , header_length)
	debug_print(PACKET_TAB + "[+]TTL:" , ttl)
	debug_print(PACKET_TAB + "[+]Protocol:" , packet_protocol)
	debug_print(PACKET_TAB + "[+]Source IPv4:" , IPv4Address(source_ip))
	debug_print(PACKET_TAB + "[+]Destination IPv4:" , IPv4Address(destination_ip))
	debug_print("\n")
	
def print_ipv6_packet_info(version_class_flowLabel , payload_length , next_header , hop_limit , source_ipv6 , destination_ipv6):
	debug_print("\033[34m++++++++++++++++++++++++++++++++++++++++++++++++++++\033[00m")
	debug_print(PACKET_TAB + "[+]Detected IPv6 packet")
	debug_print(PACKET_TAB + "[+]Payload_length:" , payload_length)
	debug_print(PACKET_TAB + "[+]Next_header:" , next_header)
	debug_print(PACKET_TAB + "[+]Hop_limit:" , hop_limit)
	debug_print(PACKET_TAB + "[+]Source IPv6:" , IPv6Address(source_ipv6))
	debug_print(PACKET_TAB + "[+]Destination IPv6:" , IPv6Address(destination_ipv6))
	debug_print("\n")
	
#create raw socket
sock = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(3))

print("\033[92m[+]Pingfisher running...\033[00m\n")
ping_counter = 0

while True:
	try:	
		#receive ethernet frames
		ethernet_frame , addr = sock.recvfrom(2048)
		
		if ethernet_frame:
			destination_mac , source_mac , protocol = unpack("! 6s 6s H" , ethernet_frame[:14])
			
			#check if the packet is IPv4 packet
			if socket.htons(protocol) == 8:
				ipv4_packet = ethernet_frame[14:]
				version_header_length = ipv4_packet[0]
				header_length = (version_header_length & 15) * 4
				ttl , packet_protocol , source_ip , destination_ip = unpack("! 8x B B 2x 4s 4s" , ipv4_packet[:20])
								
				#check if the protocol field inside IPv4 packet is ICMP
				if packet_protocol == 1:
					
					#check if the ICMP packet is a ping request
					if ipv4_packet[header_length] == 8:
						print("Ping \033[93m[REQUEST]\033[00m from {}".format(IPv4Address(source_ip)))
						
					#check if the ICMP packet is a ping response
					elif ipv4_packet[header_length] == 0:
						print("Ping \033[95m[RESPONSE]\033[00m from {}".format(IPv4Address(source_ip)))
					
					#print ethernet frame and IPv4 packet details if debug is set
					print_ethernet_frame_info(destination_mac , source_mac , protocol)
					print_ipv4_packet_info(header_length , ttl , packet_protocol , source_ip , destination_ip)
					
					#increase ping counter
					ping_counter = ping_counter + 1
				
			#check if the packet is an IPv6 packet			
			elif socket.htons(protocol) == 56710:
				ipv6_packet = ethernet_frame[14:]
				version_class_flowLabel , payload_length , next_header , hop_limit , source_ipv6 , destination_ipv6 = unpack("! 4s H B B 16s 16s" , ipv6_packet[:40])
				
				#check if it's an ICMPv6 packet
				if next_header == 58:
						
					#check if the ICMPv6 packet is a ping reqeust
					if ipv6_packet[40] == 128:
						print("Ping \033[93m[REQUEST]\033[00m from {}".format(IPv6Address(destination_ipv6)))
					
					#check if the ICMPv6 packet is a ping reply
					elif ipv6_packet[40] == 129:
						print("Ping \033[95m[RESPONSE]\033[00m from {}".format(IPv6Address(destination_ipv6)))
					
					#print ethernet frame and IPv6 packet info if debug is set
					print_ethernet_frame_info(destination_mac , source_mac , protocol)
					print_ipv6_packet_info(version_class_flowLabel , payload_length , next_header , hop_limit , source_ipv6 , destination_ipv6)
					
					#increase the ping counter
					ping_counter = ping_counter + 1
	
	#handle keyboard interruptions like "Ctrl+C"			
	except KeyboardInterrupt:
		print("\n\033[91m[+]Captured {} packets\033[00m".format(ping_counter))
		exit(0)
