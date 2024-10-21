#include "LibpcapCapture.hpp"
#include "PacketCapture.hpp"
#include "PacketProcessor.hpp"
#include <cstring>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <thread>


void print_sockaddr(struct sockaddr *sa) {
    char ip_str[INET6_ADDRSTRLEN];

    if (sa->sa_family == AF_INET) {
        // IPv4
        struct sockaddr_in *sa_in = (struct sockaddr_in *) sa;
        inet_ntop(AF_INET, &(sa_in->sin_addr), ip_str, sizeof(ip_str));
        printf("IPv4 Address: %s\n", ip_str);
        printf("Port: %d\n", ntohs(sa_in->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        // IPv6
        struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *) sa;
        inet_ntop(AF_INET6, &(sa_in6->sin6_addr), ip_str, sizeof(ip_str));
        printf("IPv6 Address: %s\n", ip_str);
        printf("Port: %d\n", ntohs(sa_in6->sin6_port));
    } else if (sa->sa_family == AF_PACKET) {
        // AF_PACKET
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
    // save to self define struct
    Packet packet;
    packet.cap_size = packet_header->caplen;
    packet.origin_size = packet_header->len;

    // 1. parsing Ethernet header
    const struct ether_header *eth_header = (struct ether_header *) packet_body;
    std::memcpy(&packet.eth_header, eth_header, sizeof(EthernetHeader));

    // 2. parsing different protocols
    uint16_t ethertype = ntohs(eth_header->ether_type);
    if (ethertype == ETHERTYPE_IP) {
        // IPv4
        const struct ip *ip_header = (struct ip *) (packet_body + sizeof(EthernetHeader));
        std::memcpy(&packet.ip_header, ip_header, sizeof(IPv4Header));

        // 3. TCP or UDP
        if (ip_header->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcp_header = (struct tcphdr *) (packet_body + sizeof(EthernetHeader) + ip_header->ip_hl * 4);
            std::memcpy(&packet.tcp_header, tcp_header, sizeof(TCPHeader));
            // tcp payload
            int tcp_header_length = tcp_header->th_off * 4;
            int ip_header_length = ip_header->ip_hl * 4;
            int headers_length = sizeof(EthernetHeader) + ip_header_length + tcp_header_length;
            int payload_length = packet_header->caplen - headers_length;
            if (payload_length > 0) {
                packet.payload = (char *) malloc(payload_length);
                std::memcpy(packet.payload, packet_body + headers_length, payload_length);
                packet.payload_size = payload_length;
            } else {
                packet.payload = nullptr;
                packet.payload_size = 0;
            }
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            const struct udphdr *udp_header = (struct udphdr *) (packet_body + sizeof(EthernetHeader) + ip_header->ip_hl * 4);
            std::memcpy(&packet.udp_header, udp_header, sizeof(UDPHeader));
            // udp payload
            int ip_header_length = ip_header->ip_hl * 4;
            int udp_header_length = sizeof(struct udphdr);
            int headers_length = sizeof(EthernetHeader) + ip_header_length + udp_header_length;
            int payload_length = packet_header->caplen - headers_length;
            if (payload_length > 0) {
                packet.payload = (char *) malloc(payload_length);
                std::memcpy(packet.payload, packet_body + headers_length, payload_length);
                packet.payload_size = payload_length;
            } else {
                packet.payload = nullptr;
                packet.payload_size = 0;
            }
        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            // ICMP
            const struct icmphdr *icmp_header = (struct icmphdr *) (packet_body + sizeof(EthernetHeader) + (ip_header->ip_hl * 4));
            std::memcpy(&packet.icmp_header, icmp_header, sizeof(ICMPHeader));
        }
    } else if (ethertype == ETHERTYPE_ARP) {
        // ARP
        const struct ether_arp *arp_header = (struct ether_arp *) (packet_body + sizeof(EthernetHeader));
        std::memcpy(&packet.arp_header, arp_header, sizeof(ARPHeader));
    }

    LibpcapCapture::processor->packet_mtx.lock();
    LibpcapCapture::processor->packet_cache.push_back(packet);
    LibpcapCapture::processor->packet_mtx.unlock();
}

std::shared_ptr<PacketProcessor> PacketCapture::processor = std::make_shared<PacketProcessor>();

LibpcapCapture::LibpcapCapture() {
    findDevices();
}

LibpcapCapture::~LibpcapCapture() {
    // close the handle
    pcap_close(handle);
    // free all devices
    pcap_freealldevs(devices);
}

void LibpcapCapture::startCapture() {
    // start the packet capture loop
    std::thread captureThread = std::thread([&]() {
        pcap_loop(handle, 0, packet_handler, nullptr);
    });
    captureThread.detach();
}

void LibpcapCapture::stopCapture() {}

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

void LibpcapCapture::findDevices() {
    // get the local network interfaces
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    for (pcap_if_t *d = devices; d != nullptr; d = d->next) {
        device_list.push_back(d);
    }
}

void LibpcapCapture::openDevice(std::string &name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    // promiscuous mode
    handle = pcap_open_live(name.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device: " << errbuf << "\n";
        pcap_freealldevs(devices);
        exit(EXIT_FAILURE);
    }
}

std::vector<std::string> LibpcapCapture::getAllDeviceName() {
    std::vector<std::string> names;
    for (auto &d: device_list) {
        names.push_back(std::string(d->name));
    }
    return names;
};