from scapy.all import *
from scapy.layers.inet import IP, TCP
import matplotlib.pyplot as plt
from collections import defaultdict

#Capture live packets
def capture_packets(interface):
    print(f"Capturing packets on {interface}...")
    packets=sniff(iface=interface, promisc=True) #promisc=True to enable promiscuous mode
    print(f"Captured {len(packets)} packets.")
    return packets

# Metric 1:Total data, total packets, min, max, avg packet sizes, and histogram
def analyze_packet_sizes(packets):
    packet_sizes=[len(pkt) for pkt in packets]
    total_data=sum(packet_sizes)
    tot_pack=len(packet_sizes)
    min_size=min(packet_sizes)
    max_size=max(packet_sizes)
    avg_size=total_data / tot_pack if tot_pack>0 else 0

    print(f"Total Data Transferred:{total_data} bytes")
    print(f"Total Packets Transferred:{tot_pack}")
    print(f"Min Packet Size:{min_size} bytes")
    print(f"Max Packet Size:{max_size} bytes")
    print(f"Average Packet Size:{avg_size:.2f} bytes")

    # Plot histogram
    plt.hist(packet_sizes, bins=20, edgecolor='black')
    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.show()

# Metric 2:Unique source-destination pairs
def find_unique_pairs(packets):
    unique_pairs=set()
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src=f"{pkt[IP].src}:{pkt[TCP].sport}"
            dst=f"{pkt[IP].dst}:{pkt[TCP].dport}"
            unique_pairs.add((src, dst))
    print(f"Unique Source-Destination Pairs:{len(unique_pairs)}")
    return unique_pairs

# Metric 3:Flows per IP (as source and destination)
def calculate_flows(packets):
    src_flows=defaultdict(int)
    dst_flows=defaultdict(int)
    data_transferred=defaultdict(int)

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src=pkt[IP].src
            dst=pkt[IP].dst
            src_port=pkt[TCP].sport
            dst_port=pkt[TCP].dport
            size=len(pkt)
            src_flows[src]+=1
            dst_flows[dst]+=1
            data_transferred[(f"{src}:{src_port}", f"{dst}:{dst_port}")]+=size

    # Find source-destination pair with max data transferred
    max_data_pair=max(data_transferred, key=data_transferred.get, default=None)
    print(f"Source Flows:{dict(src_flows)}")
    print(f"Destination Flows:{dict(dst_flows)}")
    if max_data_pair:
        print(f"Max Data Transferred:{data_transferred[max_data_pair]} bytes")
        print(f"Pair:{max_data_pair}")
    return src_flows, dst_flows

# Metric 4:Packets per second (pps) and Mbps capture rate
def analyze_speed(packets):
    timestamps=[pkt.time for pkt in packets]
    if len(timestamps)<2:
        print("Not enough packets for speed analysis.")
        return

    # Calculating pps
    duration=timestamps[-1]-timestamps[0]
    pps=len(packets) / duration if duration>0 else 0

    # Calculatinng Mbps
    total_data=sum(len(pkt) for pkt in packets)
    mbps=(total_data * 8) / (duration * 10**6) if duration>0 else 0

    print(f"Duration:{duration:.2f} seconds")
    print(f"Packets Per Second (PPS):{pps:.2f}")
    print(f"Capture Rate:{mbps:.2f} Mbps")


# Metric 5:Source and Destination IP based on conditions
def find_ips_by_conditions(packets):
    matching_packets=[]
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src_port=pkt[TCP].sport
            dst_port=pkt[TCP].dport
            ack_flag=pkt[TCP].flags & 0x10  # ACK flag is set
            ack_number=pkt[TCP].ack
            ack_last_4_digits=ack_number % 10000  # Last 4 digits of the Acknowledgement Number
            
            # Checking for conditions
            if abs(src_port-dst_port)==54286 and ack_flag and ack_last_4_digits==1203:
                src_ip=pkt[IP].src
                dst_ip=pkt[IP].dst
                matching_packets.append((src_ip, dst_ip, ack_number))
    
    print(f"Found {len(matching_packets)} packets matching the given conditions.")
    for src_ip, dst_ip, ack_number in matching_packets:
        print(f"Source IP:{src_ip}, Destination IP:{dst_ip}, Acknowledgement Number:{ack_number}")
    return matching_packets

# Metric 6:Source IP, Destination IP, and Checksum based on conditions
def find_ips_and_checksum(packets):
    matching_packets=[]
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            checksum=pkt[TCP].chksum
            urgent_pointer=pkt[TCP].urgptr
            sequence_number=pkt[TCP].seq
            

            # Convert checksum to hexadecimal and check conditions
            checksum_hex=hex(checksum)
            if checksum_hex[:3]=='0xb5' and urgent_pointer==0 and str(sequence_number).endswith('6183'):
                src_ip=pkt[IP].src
                dst_ip=pkt[IP].dst
                matching_packets.append((src_ip, dst_ip, checksum_hex))
    
    print(f"Found {len(matching_packets)} packets matching the checksum conditions.")
    for src_ip, dst_ip, checksum in matching_packets:
        print(f"Source IP:{src_ip}, Destination IP:{dst_ip}, Checksum:{checksum}")
    return matching_packets


# Metric 7:Count of packets where sum of source and destination ports is between 10,000 and 20,000
def count_packets_by_port_range(packets):
    count=0
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src_port=pkt[TCP].sport
            dst_port=pkt[TCP].dport
            port_sum=src_port + dst_port
            if 10000<=port_sum<=20000:
                count+=1
    
    print(f"Number of packets where source + destination ports are between 10,000 and 20,000:{count}")
    return count

# Metric 8:Find packets with Acknowledgement Number in the specified range
def find_packets_by_ack_range(packets):
    matching_packets=[]
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            ack_number=pkt[TCP].ack
            if 1678999000<=ack_number<=1700000000:
                src_ip=pkt[IP].src
                dst_ip=pkt[IP].dst
                matching_packets.append((src_ip, dst_ip, ack_number))
    
    print(f"Found {len(matching_packets)} packets with Acknowledgement Number in the specified range.")
    for src_ip, dst_ip, ack_number in matching_packets:
        print(f"Source IP:{src_ip}, Destination IP:{dst_ip}, Acknowledgement Number:{ack_number}")
    return matching_packets

# Main Function
def main():
    interface="lo"
    packets=capture_packets(interface)

    print("\n=== Metric 1:Packet Sizes ===")
    analyze_packet_sizes(packets)

    print("\n=== Metric 2:Unique Source-Destination Pairs ===")
    unique_pairs=find_unique_pairs(packets)
    print(unique_pairs)

    print("\n=== Metric 3:Flows Per IP ===")
    calculate_flows(packets)

    print("\n=== Metric 4:Speed Analysis ===")
    analyze_speed(packets)

    print("\n=== Metric 5:Find Source and Destination IP based on conditions ===")
    find_ips_by_conditions(packets)

    print("\n=== Metric 6:Find Source IP, Destination IP, and Checksum ===")
    find_ips_and_checksum(packets)

    print("\n=== Metric 7:Count Packets with Source + Destination Ports between 10,000 and 20,000 ===")
    count_packets_by_port_range(packets)

    print("\n=== Metric 8:Find Packets with Acknowledgement Number in Specified Range ===")
    find_packets_by_ack_range(packets)

if __name__=="__main__":
    main()
