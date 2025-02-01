#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unordered_map>
#include <vector>
#include <iostream>
#include <fstream>
#include <limits.h>

#define MAX_PACKETS 328623

using namespace std;

unordered_map<string, int> src_flows;
unordered_map<string, int> dst_flows;
unordered_map<string, int> dataTrans;
unordered_map<string, bool> unique_pairs;
unordered_map<string, uint64_t> ip_src_flows;
unordered_map<string, uint64_t> ip_dst_flows; 
vector<tuple<string, string, int, int, uint32_t>> matching_ips_1; // For Condition 1
vector<tuple<string, string, uint16_t>> matching_ips_2;  // For Condition 2
vector<tuple<string, string, uint32_t>> matching_ips_4;

int portCount=0;  // Condition 3 counter

int tot_packets=0;
int total_data=0;
int min_size=INT_MAX;
int max_size=0;
double avg_size=0;
double start_time=0;
double end_time=0;
vector<int> packet_sizes;
 ofstream output_file("output.txt");

void analyze_packet_conditions(const struct ip *ip_header, const struct tcphdr *tcp_header) {
    int src_port=ntohs(tcp_header->th_sport);
    int dst_port=ntohs(tcp_header->th_dport);
    int abs_diff=abs(src_port - dst_port);
    uint32_t ack_number=ntohl(tcp_header->th_ack);
    uint32_t seq_number=ntohl(tcp_header->th_seq);
    uint16_t checksum=ntohs(tcp_header->th_sum);
    uint16_t urgent_pointer=ntohs(tcp_header->th_urp);

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Condition 1: Absolute difference of ports=54286, ACK flag is set, last 4 digits of ACK number=1203
    if (abs_diff==54286 && (tcp_header->th_flags & TH_ACK)) {
        if (ack_number % 10000==1203) {
            // matching_ips_1.push_back({src_ip, dst_ip});
            matching_ips_1.push_back({src_ip, dst_ip, src_port, dst_port, ack_number});
        }
    }

    // Condition 2: Checksum starts with 0xb5__, Urgent Pointer=0, Last 4 digits of Sequence Number=6183
    if ((checksum & 0xFF00)==0xB500 && urgent_pointer==0) {
        if (seq_number % 10000==6183) {
            matching_ips_2.push_back({src_ip, dst_ip, checksum});
        }
    }

    // Condition 3: Count packets where sum of source and destination ports is between 10,000 and 20,000
    int port_sum=src_port+dst_port;
    if (port_sum >= 10000 && port_sum <= 20000) {
        portCount++;
    }

    // Condition 4: Find packets with ACK number between 1678999000 and 1700000000
    

    if (ack_number >= 1678999000 && ack_number <= 1700000000) {
    matching_ips_4.push_back({src_ip, dst_ip, ack_number});
    }


    // Track unique source-destination IP:port pairs
    string src_pair=string(src_ip)+":"+to_string(src_port);
    string dst_pair=string(dst_ip)+":"+to_string(dst_port);
    string unique_pair=src_pair+" -> "+dst_pair;
    unique_pairs[unique_pair]=true;

    // Track source and destination flows
    ip_src_flows[src_ip]++;
    ip_dst_flows[dst_ip]++;

    // Track total data transferred by each source-destination pair
    string flow_pair=string(src_ip)+":"+to_string(src_port)+" -> "+string(dst_ip)+":"+to_string(dst_port);
    dataTrans[flow_pair] += ntohs(tcp_header->th_off);  // Add packet size to the flow's total
}

void process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header=(struct ip *)(packet+14);
    struct tcphdr *tcp_header=(struct tcphdr *)(packet+14+(ip_header->ip_hl * 4));

    int packet_size=header->len;
    tot_packets++;
    total_data += packet_size;

    packet_sizes.push_back(packet_size);

    if (packet_size < min_size) min_size=packet_size;
    if (packet_size > max_size) max_size=packet_size;
    avg_size=(double)total_data / tot_packets;


    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    if (tot_packets==1) start_time=header->ts.tv_sec+header->ts.tv_usec / 1e6;
    end_time=header->ts.tv_sec+header->ts.tv_usec / 1e6;

    analyze_packet_conditions(ip_header, tcp_header);
}

void display_results() {
    printf("\n Packet Statistics:\n");
    output_file << "\n Packet Statistics:\n";
    printf("  - Total Packets: %d\n", tot_packets);
    output_file << "  - Total Packets: " << tot_packets << endl;
    printf("  - Total Data Transferred: %d bytes\n", total_data);
    output_file << "  - Total Data Transferred: " << total_data << " bytes" << endl;
    printf("  - Min Packet Size: %d bytes\n", min_size);
    output_file << "  - Min Packet Size: " << min_size << " bytes" << endl;
    printf("  - Max Packet Size: %d bytes\n", max_size);
    output_file << "  - Max Packet Size: " << max_size << " bytes" << endl;
    printf("  - Avg Packet Size: %.2f bytes\n", avg_size);
    output_file << "  - Avg Packet Size: " << avg_size << " bytes" << endl;

    // Call the Python script to generate and save the histogram
    string command="python histogram.py";

    system(command.c_str()); // Execute the Python script

    // Append packet sizes to the command
    for (int size : packet_sizes) {
        command += " "+std::to_string(size);
    }


    // New feature: Display unique source-destination pairs
    printf("\n[Unique Source-Destination IP:Port Pairs]\n");
    output_file << "\n[Unique Source-Destination IP:Port Pairs]\n";
    for (const auto &unique_pair : unique_pairs) {
        printf("  - %s\n", unique_pair.first.c_str());
        output_file << "  - " << unique_pair.first << endl;
    }

    // Display IP source flows dictionary
    printf("\n[Source IP Flows]\n");
    output_file << "\n[Source IP Flows]\n";
    for (const auto &src_flow : ip_src_flows) {
        printf("  - %s : %lu flows\n", src_flow.first.c_str(), src_flow.second);
        output_file << "  - " << src_flow.first << " : " << src_flow.second << " flows" << endl;
    }

    // Display IP destination flows dictionary
    printf("\n[Destination IP Flows]\n");
    output_file << "\n[Destination IP Flows]\n";
    for (const auto &dst_flow : ip_dst_flows) {
        printf("  - %s : %lu flows\n", dst_flow.first.c_str(), dst_flow.second);
        output_file << "  - " << dst_flow.first << " : " << dst_flow.second << " flows" << endl;
    }

    // Find source-destination pair that transferred the most data
    uint64_t max_data=0;
    string max_data_flow;
    for (const auto &flow : dataTrans) {
        if (flow.second > max_data) {
            max_data=flow.second;
            max_data_flow=flow.first;
        }
    }

    printf("\n[Source-Destination Pair with Most Data Transferred]\n");
    output_file << "\n[Source-Destination Pair with Most Data Transferred]\n";
    printf("  - %s : %lu bytes\n", max_data_flow.c_str(), max_data);
    output_file << "  - " << max_data_flow << " : " << max_data << " bytes" << endl;

    // Calculate capture speed
    double cap_time=end_time - start_time;
    if (cap_time > 0) {
        double pps=tot_packets / cap_time;
        double mbps=(total_data * 8.0) / (cap_time * 1e6);
        printf("\n[Capture Speed]\n");
        output_file << "\n[Capture Speed]\n";
        printf("  - Packets per second (pps): %.2f\n", pps);
        output_file << "  - Packets per second (pps): " << pps << endl;
        printf("  - Megabits per second (Mbps): %.2f\n", mbps);
        output_file << "  - Megabits per second (Mbps): " << mbps << endl;
    } else {
        printf("\n[Capture Speed]\n");
        output_file << "\n[Capture Speed]\n";
        printf("  - Unable to calculate due to insufficient time data.\n");
        output_file << "  - Unable to calculate due to insufficient time data." << endl;
    }
}

void MatchCondition() {
    printf("\n[Condition 1: Matching IPs Based on ACK Criteria]\n");
    output_file << "\n[Condition 1: Matching IPs Based on ACK Criteria]\n";
    // for (const auto &ip_tuple : matching_ips_1) {
    //     printf("  - Source IP: %s, Destination IP: %s\n", ip_pair.first.c_str(), ip_pair.second.c_str());
    //     output_file << "  - Source IP: " << ip_pair.first << ", Destination IP: " << ip_pair.second << endl;
    // }
    for (const auto &ip_tuple : matching_ips_1) {
    printf("  - Source IP: %s, Destination IP: %s, Source Port: %d, Destination Port: %d, ACK Number: 0x%08X\n",
           get<0>(ip_tuple).c_str(), get<1>(ip_tuple).c_str(), get<2>(ip_tuple), get<3>(ip_tuple), get<4>(ip_tuple));
    output_file << "  - Source IP: " << get<0>(ip_tuple) << ", Destination IP: " << get<1>(ip_tuple) 
                << ", Source Port: " << get<2>(ip_tuple) << ", Destination Port: " << get<3>(ip_tuple) 
                << ", ACK Number: 0x" << std::hex << get<4>(ip_tuple) << std::dec << endl;
    }

    printf("\n[Condition 2: Matching IPs Based on Checksum Criteria]\n");
    output_file << "\n[Condition 2: Matching IPs Based on Checksum Criteria]\n";
    for (const auto &ip_tuple : matching_ips_2) {
        printf("  - Source IP: %s, Destination IP: %s, Checksum: 0x%04X\n", get<0>(ip_tuple).c_str(), get<1>(ip_tuple).c_str(), get<2>(ip_tuple));
        output_file << "  - Source IP: " << get<0>(ip_tuple) << ", Destination IP: " << get<1>(ip_tuple) << ", Checksum: 0x" << hex << get<2>(ip_tuple) << dec << endl;
    }



    printf("\n[Condition 3: Count of Packets with Port Sum between 10,000 and 20,000]\n");
    output_file << "\n[Condition 3: Count of Packets with Port Sum between 10,000 and 20,000]\n";
    printf("  - Total Packets: %d\n", portCount);
    output_file << "  - Total Packets: " << portCount << endl;

    printf("\n[Condition 4: Matching IPs Based on ACK Number Range]\n");
    output_file << "\n[Condition 4: Matching IPs Based on ACK Number Range]\n";
    for (const auto &ip_tuple : matching_ips_4) {
        printf("  - Source IP: %s, Destination IP: %s, ACK Number: %u\n", 
               get<0>(ip_tuple).c_str(), get<1>(ip_tuple).c_str(), get<2>(ip_tuple));
        output_file << "  - Source IP: " << get<0>(ip_tuple) << ", Destination IP: " << get<1>(ip_tuple) << ", ACK Number: " << get<2>(ip_tuple) << endl;
    }
}

void capture_packets(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;

    handle=pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    printf(" Capturing packets on interface: %s\n", interface);

    while (tot_packets < MAX_PACKETS) {
        packet=pcap_next(handle, &header);
        if (packet==NULL) continue;
        process_packet(&header, packet);
    }

    pcap_close(handle);
    display_results();
    MatchCondition();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    

    capture_packets(argv[1]);


    //     // Close the output file
    output_file.close();

    return 0;
}
