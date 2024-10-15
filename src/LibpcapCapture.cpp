#include "LibpcapCapture.hpp"
#include "PacketCapture.hpp"
#include <cstdlib>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
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
    std::cout << "Captured a packet with length: " << packet_header->len << " bytes\n";

    // IP header starts after the Ethernet header (14 bytes for Ethernet)
    const struct ip *ip_header = (struct ip *) (packet_body + 14);

    // Print source and destination IP addresses
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    std::cout << "Source IP: " << src_ip << "\n";
    std::cout << "Destination IP: " << dst_ip << "\n";

    // Only proceed if it's a TCP packet
    if (ip_header->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp_header = (struct tcphdr *) (packet_body + 14 + (ip_header->ip_hl * 4));
        std::cout << "Source Port: " << ntohs(tcp_header->source) << "\n";
        std::cout << "Destination Port: " << ntohs(tcp_header->dest) << "\n";
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
    if (filter == "tcp") {
        // set filter to capture only TCP packets
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Couldn't parse filter: " << pcap_geterr(handle) << "\n";
            exit(EXIT_FAILURE);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Couldn't install filter: " << pcap_geterr(handle) << "\n";
            exit(EXIT_FAILURE);
        }
    }
}
