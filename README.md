# Packet Sniffing and Analysis using C++

## Overview
This assignment involves packet sniffing and analysis using C++ with the libpcap library. The script `sniffer.cpp` captures live network traffic or reads from a `.pcap` file, extracts meaningful insights, and performs various analyses such as packet size distribution, unique source-destination pairs, flow analysis, and speed calculations.

Additionally, we used **Kali Linux Live Boot** to run this project, leveraging its built-in networking tools. The `.pcap` file was replayed using `tcpreplay` for controlled network traffic analysis.

## Features
The program performs the following tasks:

1. **Packet Capture**: Captures live packets from a specified network interface.
2. **Packet Size Analysis**: 
   - Calculates total data transferred
   - Tracks total packets, min/max/average packet size
   - Generates histogram using Python script
3. **Source-Destination Pairs**: Identifies unique source-destination (IP:port) pairs.
4. **Traffic Flow Analysis**:
   - Computes number of flows per IP address (both as source and destination)
   - Identifies source-destination pair that transferred the most data
5. **Speed Analysis**:
   - Calculates packets per second (PPS) and Mbps capture rate
6. **Custom Condition-Based Packet Filtering**:
   - Identifies packets with specific port differences and ACK numbers
   - Tracks packets with checksums starting with 0xB5
   - Counts packets where source and destination port sums fall within a range
   - Finds packets with acknowledgment numbers within specific ranges

## Prerequisites

### Required Packages
Install the necessary dependencies on Kali Linux:

```
sudo apt update
sudo apt install libpcap-dev g++ python3-matplotlib tcpreplay
```

### Kali Linux Live Boot Setup
1. Download Kali Linux ISO from the official website
2. Create bootable USB using Rufus or Balena Etcher
3. Boot from USB and select Live Mode
4. Install required packages mentioned above

## Compilation and Usage

### Compiling the Code
```
g++ -o sniffer sniffer.cpp -lpcap
```

### Running the Sniffer
To capture live packets from a network interface:
```
sudo ./sniffer <interface_name>
```
Replace `<interface_name>` with your network interface (e.g., eth0, wlan0, lo).

### Checking Network Interfaces
To list available network interfaces:
```
ip a
```
or
```
ifconfig
```

### Working with PCAP Files
To capture traffic to a PCAP file using tcpdump:
```
sudo tcpdump -i <interface> -w capture.pcap
```

To replay a PCAP file:
```
sudo tcpreplay -i <interface> capture.pcap
sudo tcpreplay -i <interface> --mbps=100 capture.pcap   #to increase replay speed
```

## Output
The program generates several output files:
- `output.txt`: Contains detailed analysis including:
  - Packet statistics
  - Unique source-destination pairs
  - Flow analysis
  - Speed metrics
  - Condition-based filtering results
- `packet_size.txt`: Raw packet size data
- `packet_size_histogram.png`: Visual representation of packet size distribution

## Visualization
The Python script `histogram.py` creates a histogram of packet sizes using matplotlib. It reads data from `packet_size.txt` and generates `packet_size_histogram.png`.

To run the histogram generator separately:
```
python3 histogram.py
```

## Author
Assignment by Nakul Ranka(24120035) and Saumya Jaiswal(21110186). Reach out for questions!

## Notes
- Ensure you have root privileges when running the sniffer
- The program is set to capture a maximum of 328623 packets by default
- Modify MAX_PACKETS in sniffer.cpp to change the capture limit
- Use Kali Linux for best compatibility and tool availability
