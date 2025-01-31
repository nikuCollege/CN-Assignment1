# Packet Sniffing and Analysis using Scapy

## Overview
This assignment involves packet sniffing and analysis using Python's Scapy library. The script `sniff.py` captures live network traffic or reads from a `.pcap` file, extracts meaningful insights, and performs various analyses such as packet size distribution, unique source-destination pairs, flow analysis, and speed calculations.

Additionally, we used **Kali Linux Live Boot** to run this project, leveraging its built-in networking tools. The `.pcap` file was replayed using `tcpreplay` for controlled network traffic analysis.

## Features
The script performs the following tasks:

1. **Packet Capture**: Captures live packets from a specified network interface.
2. **Packet Size Analysis**: Calculates the total amount of data transferred, total packets, min/max/average packet size, and plots a histogram.
3. **Source-Destination Pairs**: Identifies unique source-destination (IP:port) pairs.
4. **Traffic Flow Analysis**:
   - Computes the number of flows per IP address (both as source and destination).
   - Identifies the source-destination pair that transferred the most data.
5. **Speed Analysis**:
   - Calculates packets per second (PPS) and Mbps capture rate.
6. **Custom Condition-Based Packet Filtering**:
   - Identifies packets based on given port, acknowledgment number, and checksum conditions.
   - Counts packets where the sum of source and destination ports falls within a range.
   - Finds packets with acknowledgment numbers within a specific range.
7. **PCAP File Replay with tcpreplay**:
   - Used `tcpreplay` on Kali Linux to replay the captured packets from a `.pcap` file named `8.pcap`.
   - This allowed for controlled replay and analysis of network traffic.

## Kali Linux Live Boot Setup
We used **Kali Linux Live Boot** to run this project without installing it on the system. The setup involved:
1. Downloading the Kali Linux ISO from the official website.
2. Creating a bootable USB drive using tools like **Rufus** or **Balena Etcher**.
3. Booting the system from the USB by changing the BIOS boot order.
4. Selecting the **Live Mode** option to run Kali Linux without installation.
5. Installing necessary tools (`tcpreplay`, `Scapy`, etc.) and running the script.

## Concepts Explained
### Packet Sniffing
Packet sniffing is the process of capturing network packets to analyze traffic. This is useful for debugging, security monitoring, and performance analysis.

### PCAP Files
PCAP (Packet Capture) files store network traffic captured by tools like Wireshark or Scapy. These files can be replayed for analysis.

### tcpreplay
`tcpreplay` is a Linux tool that allows the replaying of previously captured `.pcap` files on a network interface. It helps in:
- Testing network applications under real traffic conditions.
- Simulating attacks for security analysis.
- Debugging network behavior.

## Prerequisites
Ensure you have Python installed along with the required dependencies:
```
pip install scapy matplotlib
```

Additionally, install `tcpreplay` if not already installed:

```
sudo apt install tcpreplay
```

## Usage

### Running the Script
To capture live packets from a network interface:

```
sudo python3 sniff.py
```

Make sure to replace `lo` in the script with the correct network interface name.

### Running with a PCAP File
To analyze an existing `.pcap` file, modify the script to load the file instead of capturing live traffic:

### Replaying PCAP with tcpreplay
To replay the `8.pcap` file using `tcpreplay` on Kali Linux, run:

```
sudo tcpreplay -i lo 8.pcap
```

This sends the packets from `8.pcap` onto the network interface `lo` for further analysis.

### Output
The script outputs various metrics, including:
- Total data transferred
- Packet size statistics
- Unique IP pairs
- Flow statistics
- Speed analysis
- Specific packet filtering based on given conditions

Additionally, a histogram of packet sizes is displayed.

## Customization
Modify the script as needed:
- Change the network interface for live capture.
- Update conditions for filtering packets.
- Enhance visualization using additional matplotlib features.

## Author
Assignment by Nakul Ranka(24120035) and Saumya Jaiswal(21110186). Reach out for questions!

