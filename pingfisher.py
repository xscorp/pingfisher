import socket
from struct import unpack
from sys import exit
from ipaddress import IPv4Address , IPv6Address
from argparse import ArgumentParser

#parse command line arguments
parser = ArgumentParser(description="")
parser.add_argument("--debug" , "-d" , help="Debug mode" , action="store_true" , default = False)
arguments = parser.parse_args()

#function to print the debug information only when the debug flag is set
def debug_print(*msg):
	if arguments.debug:
		for data in msg:
			print(data)

#create raw socket
sock = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(3))

print("\033[92m[+]Pingfisher running...\033[00m\n")
ping_counter = 0

while True:
	try:	
		#receive ethernet frames
		ethernet_frame , addr = sock.recvfrom(2048)
		
		if ethernet_frame:
			debug_print("====================================================")
			debug_print("[+]Received Ethernet frame")
			debug_print("Printing raw frame data:\n" , ethernet_frame)
			destination_mac , source_mac , protocol = unpack("! 6s 6s H" , ethernet_frame[:14])
			debug_print("[+]Source mac:" , source_mac)
			debug_print("[+]Destination mac:" , destination_mac)
			debug_print("[+]Protocol:" , socket.htons(protocol))

			#check if the packet is IPv4 packet
			if socket.htons(protocol) == 8:
				debug_print("[+]Detected IPv4 packet")
				ipv4_packet = ethernet_frame[14:]
				version_header_length = ipv4_packet[0]
				header_length = (version_header_length & 15) * 4
				ttl , packet_protocol , source_ip , destination_ip = unpack("! 8x B B 2x 4s 4s" , ipv4_packet[:20])
				debug_print("Protocol inside IPv4:" , packet_protocol)
				
				#check if the protocol field inside IPv4 packet is ICMP
				if packet_protocol == 1:
					
					#check if the ICMP packet is a ping request
					if ipv4_packet[header_length] == 8:
						print("Ping \033[93m[REQUEST]\033[00m from {}".format(IPv4Address(source_ip)))
						
					#check if the ICMP packet is a ping response
					elif ipv4_packet[header_length] == 0:
						print("Ping \033[95m[RESPONSE]\033[00m from {}".format(IPv4Address(source_ip)))
					
					#increase ping counter
					ping_counter = ping_counter + 1
				
			#check if the packet is an IPv6 packet			
			elif socket.htons(protocol) == 56710:
				debug_print("====================================================")
				debug_print("[+]Detected IPv6 packet")
				ipv6_packet = ethernet_frame[14:]
				version_class_flowLabel , payload_length , next_header , hop_limit , source_ipv6 , destination_ipv6 = unpack("! 4s H B B 16s 16s" , ipv6_packet[:40])
				debug_print("[+]Payload_length:" , payload_length)
				debug_print("[+]Next_header:" , next_header)
				debug_print("[+]Hop_limit:" , hop_limit)
				debug_print("[+]Source IPv6:" , IPv6Address(source_ipv6))
				debug_print("[+]Destination IPv6:" , IPv6Address(destination_ipv6))
				
				#check if it's an ICMPv6 packet
				if next_header == 58:
					
					#check if the ICMPv6 packet is a ping reqeust
					if ipv6_packet[40] == 128:
						print("Ping \033[93m[REQUEST]\033[00m from {}".format(IPv6Address(destination_ipv6)))
					
					#check if the ICMPv6 packet is a ping reply
					elif ipv6_packet[40] == 129:
						print("Ping \033[95m[RESPONSE]\033[00m from {}".format(IPv6Address(destination_ipv6)))
					
					#increase the ping counter
					ping_counter = ping_counter + 1
	
	#handle keyboard interruptions like "Ctrl+C"			
	except KeyboardInterrupt:
		print("\n\033[91m[+]Captured {} packets\033[00m".format(ping_counter))
		exit(0)
