#include "LibpcapCapture.hpp"
#include "PacketCapture.hpp"
#include <cstdlib>
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <string>
#include <vector>


void print_sockaddr(struct sockaddr *sa) {
    char ip_str[INET6_ADDRSTRLEN];// 适用于 IPv4 和 IPv6

    // 根据地址类型输出不同的内容
    if (sa->sa_family == AF_INET) {
        // IPv4 地址
        struct sockaddr_in *sa_in = (struct sockaddr_in *) sa;
        inet_ntop(AF_INET, &(sa_in->sin_addr), ip_str, sizeof(ip_str));
        printf("IPv4 Address: %s\n", ip_str);
        printf("Port: %d\n", ntohs(sa_in->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        // IPv6 地址
        struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *) sa;
        inet_ntop(AF_INET6, &(sa_in6->sin6_addr), ip_str, sizeof(ip_str));
        printf("IPv6 Address: %s\n", ip_str);
        printf("Port: %d\n", ntohs(sa_in6->sin6_port));
    } else if (sa->sa_family == AF_PACKET) {
        // 处理 AF_PACKET 类型的地址
        printf("AF_PACKET (raw packet interface)\n");
    } else {
        printf("Unknown AF family: %d\n", sa->sa_family);
    }
}

void print_device_info(const pcap_if_t *device) {
    std::cout << "[" << device->name << "]\n";

    std::cout << "Description: ";
    if (device->description != nullptr)
        std::cout << device->description << std::endl;
    else
        std::cout << "NULL" << std::endl;

    pcap_addr *address = device->addresses;
    int cnt = 1;
    while (address) {
        std::cout << "Addr" << std::to_string(cnt) << ":\n";
        cnt++;

        if (address->addr)
            print_sockaddr(address->addr);
        if (address->netmask)
            print_sockaddr(address->netmask);

        address = address->next;
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
    std::cout << "-----------------------------\n";

    std::cout << "Captured a packet with length: " << packet_header->len << " bytes\n";

    // parse Ethernet header
    struct ether_header *eth_header = (struct ether_header *) packet_body;

    // extract and print source and destination MAC addresses
    char src_mac[18], dst_mac[18];
    sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            eth_header->ether_shost[0], eth_header->ether_shost[1],
            eth_header->ether_shost[2], eth_header->ether_shost[3],
            eth_header->ether_shost[4], eth_header->ether_shost[5]);
    sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            eth_header->ether_dhost[0], eth_header->ether_dhost[1],
            eth_header->ether_dhost[2], eth_header->ether_dhost[3],
            eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    std::cout << "Source MAC: " << src_mac << "\n";
    std::cout << "Destination MAC: " << dst_mac << "\n";

    // check for IP or ARP packets
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        const struct ip *ip_header = (struct ip *) (packet_body + sizeof(struct ether_header));

        // print source and destination IP addresses
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        std::cout << "Source IP: " << src_ip << "\n";
        std::cout << "Destination IP: " << dst_ip << "\n";

        // check for TCP or UDP packets
        if (ip_header->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcp_header = (struct tcphdr *) (packet_body + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
            std::cout << "Protocol: TCP\n";
            std::cout << "Source Port: " << ntohs(tcp_header->source) << "\n";
            std::cout << "Destination Port: " << ntohs(tcp_header->dest) << "\n";
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            const struct udphdr *udp_header = (struct udphdr *) (packet_body + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
            std::cout << "Protocol: UDP\n";
            std::cout << "Source Port: " << ntohs(udp_header->source) << "\n";
            std::cout << "Destination Port: " << ntohs(udp_header->dest) << "\n";
        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            // parse ICMP packet
            const struct icmphdr *icmp_header = (struct icmphdr *) (packet_body + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
            std::cout << "Protocol: ICMP\n";
            std::cout << "ICMP Type: " << (unsigned int) icmp_header->type << "\n";
            std::cout << "ICMP Code: " << (unsigned int) icmp_header->code << "\n";

            // check if it's an echo request or reply (used in ping)
            if (icmp_header->type == ICMP_ECHO) {
                std::cout << "ICMP Message: Echo Request\n";
            } else if (icmp_header->type == ICMP_ECHOREPLY) {
                std::cout << "ICMP Message: Echo Reply\n";
            }
        }
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        // parse ARP header
        struct ether_arp *arp_header = (struct ether_arp *) (packet_body + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp_header->arp_spa, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp_header->arp_tpa, dst_ip, INET_ADDRSTRLEN);

        std::cout << "Protocol: ARP\n";
        std::cout << "Source IP: " << src_ip << "\n";
        std::cout << "Destination IP: " << dst_ip << "\n";
    }

    std::cout << "-----------------------------\n";
}

LibpcapCapture::LibpcapCapture() {
    // get the local network interfaces
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    // show the interface list
    for (pcap_if_t *d = devices; d != nullptr; d = d->next) {
        print_device_info(d);
    }

    // open device for live capture
    // TODO: choose a interface
    handle = pcap_open_live(devices->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device: " << errbuf << "\n";
        pcap_freealldevs(devices);
        exit(EXIT_FAILURE);
    }
}

LibpcapCapture::~LibpcapCapture() {
    // close the handle
    pcap_close(handle);

    // free all devices
    pcap_freealldevs(devices);
}

void LibpcapCapture::startCapture() {
    // start the packet capture loop
    pcap_loop(handle, 0, packet_handler, nullptr);
}

void LibpcapCapture::stopCapture() {}

std::vector<Packet> LibpcapCapture::getCapturedPackets() {
    return {};
}

void LibpcapCapture::setFilter(const std::string &filter) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't parse filter: " << pcap_geterr(handle) << "\n";
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter: " << pcap_geterr(handle) << "\n";
        exit(EXIT_FAILURE);
    }
}
