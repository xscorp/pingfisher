# pingfisher
pingfisher is a tool to capture ICMPv4 and ICMPv6 ping requests and reply.

## Why pingfisher?
I mainly made it for the purpose of assistence in CTFs. Suppose you have a blind RCE exploit code which accepts commands from you and executes them on target system but doesn't produces any output. To check if it's actually working, probably the easiest method is to ping your system from the remote system through the exploit and capture the ICMP packets in your system through any linux utility like **tcpdump**.
I found that sometimes, **tcpdump** was unable to capture ping requests(don't know why). Also, the representation of it's output is not that friendly. So I decided to create a tool that capture ICMP requests in both IPv4 and IPv6 packets.

## How does it work?
It works by creating a raw socket and listening for ethernet frames on the network. Upon receiving them, it unpacks the ethernet frame and checks if the payload inside it is an IPv4 or IPv6 packet. If it's an IPv4 or IPv6 packet, it further unpacks it and checks whether the payload contained in it is an ICMPv4 or ICMPv6 packet. If it is an ICMP packet, it further unpacks it and checks whether it is an ICMP request or ICMP reply.

## Command arguments
