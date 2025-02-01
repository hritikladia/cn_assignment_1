from scapy.all import rdpcap, DNS, Raw
import matplotlib.pyplot as plt
from collections import defaultdict
import time
import socket

# Load the PCAP file
pcap_file = "0.pcap"  # Replace with actual file path

# Resolve IMS Server IP 
ims_server = "ims.iitgn.ac.in"  
ims_ip = socket.gethostbyname(ims_server)
print(f"Resolved IMS Server IP: {ims_ip}")

# Show progress of loading the PCAP file
print("Loading PCAP file...")
load_start_time = time.time()
packets = rdpcap(pcap_file)  # Load packets in bulk
total_packets = len(packets)
load_time = time.time() - load_start_time
print(f"PCAP file loaded in {load_time:.2f} seconds. Total packets: {total_packets}")

# Metrics Initialization
total_bytes = 0
packet_sizes = []
source_dest_pairs = set()
source_flows = defaultdict(int)
destination_flows = defaultdict(int)
data_transfer = defaultdict(int)
source_dest_port_pairs = set()
imss_connections = set()
ims_courses = set()
port_4321_bytes = 0
superuser_count = 0

# Show progress of packet processing
start_time = time.time()
for i, packet in enumerate(packets):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        src_port = packet["TCP"].sport
        dst_port = packet["TCP"].dport
        size = len(packet.original)
        total_bytes += size
        packet_sizes.append(size)
        source_dest_pairs.add((src_ip, dst_ip))
        source_dest_port_pairs.add((src_ip, src_port, dst_ip, dst_port))
        source_flows[src_ip] += 1
        destination_flows[dst_ip] += 1
        data_transfer[(src_ip, src_port, dst_ip, dst_port)] += size
        
        # Count unique connections to IMS server
        if dst_ip == ims_ip:
            imss_connections.add((src_ip, dst_ip))
        
        # Count total data transferred over port 4321
        if dst_port == 4321:
            port_4321_bytes += size
        
        # Count occurrences of "superuser"
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            superuser_count += payload.lower().count("superuser")

# Compute Min, Max, and Average Packet Size
min_packet_size = min(packet_sizes)
max_packet_size = max(packet_sizes)
avg_packet_size = total_bytes / total_packets

# Save Metrics and Results to a File
with open("pcap_analysis_results.txt", "w") as f:
    f.write(f"Total bytes transferred: {total_bytes} bytes ({total_bytes / (1024 * 1024):.2f} MB)\n")
    f.write(f"Total packets: {total_packets}\n")
    f.write(f"Min packet size: {min_packet_size} bytes\n")
    f.write(f"Max packet size: {max_packet_size} bytes\n")
    f.write(f"Average packet size: {avg_packet_size:.2f} bytes\n")
    f.write(f"Unique Source-Destination Pairs: {len(source_dest_pairs)}\n")
    f.write(f"Top Source-Destination Pair (by data transferred): {max(data_transfer, key=data_transfer.get)} ({max(data_transfer.values())} bytes)\n")
    f.write("\nPCAP Specific Questions:\n")
    f.write(f"Q1: Unique connections to IMS Server: {len(imss_connections)}\n")
    f.write(f"Q3: Total data transferred over port 4321: {port_4321_bytes} bytes\n")
    f.write(f"Q4: Total occurrences of 'SuperUser': {superuser_count}\n")

# Search for "course" in the raw payload of each packet and save results
with open("course_search_results.txt", "w") as course_file:
    for packet in packets:
        if packet.haslayer(Raw):  # Check if packet has raw data
            raw_data = packet[Raw].load.decode(errors="ignore")  # Decode payload
            if "course" in raw_data.lower():  # Search for "course"
                course_file.write(f"Found in Packet: {packet.summary()}\n")
                course_file.write(f"Packet Data: {raw_data}\n\n")

print("Course-related packet data has been saved to 'course_search_results.txt'.")
