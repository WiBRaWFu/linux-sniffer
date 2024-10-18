#include "PacketProcessor.hpp"
#include <arpa/inet.h>
#include <mutex>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string>
#include <thread>

PacketProcessor::PacketProcessor() {
    std::thread pt([&]() {
        process();
    });
    pt.detach();
}

PacketProcessor::~PacketProcessor() {}

void PacketProcessor::process() {
    while (true) {
        info_mtx.lock();
        int len = info_cache.size();

        packet_mtx.lock();
        for (int i = len; i < packet_cache.size(); i++) {
            Packet &packet = packet_cache[i];

            char src_mac[18], dst_mac[18];
            sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    packet.eth_header.src_mac[0], packet.eth_header.src_mac[1],
                    packet.eth_header.src_mac[2], packet.eth_header.src_mac[3],
                    packet.eth_header.src_mac[4], packet.eth_header.src_mac[5]);
            sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    packet.eth_header.dst_mac[0], packet.eth_header.dst_mac[1],
                    packet.eth_header.dst_mac[2], packet.eth_header.dst_mac[3],
                    packet.eth_header.dst_mac[4], packet.eth_header.dst_mac[5]);

            std::string message = std::string(src_mac) + "  " + std::string(dst_mac);

            if (ntohs(packet.eth_header.ethertype) == ETHERTYPE_IP) {
                // print source and destination IP addresses
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(packet.ip_header.src_ip), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(packet.ip_header.dest_ip), dst_ip, INET_ADDRSTRLEN);

                message += "  " + std::string(src_ip) + "  " + std::string(dst_ip);

                // check for TCP or UDP packets
                if (packet.ip_header.protocol == IPPROTO_TCP) {
                    message += "   tcp";
                    int src_port = ntohs(packet.transport_layer.tcp_header.src_port);
                    int dst_port = ntohs(packet.transport_layer.tcp_header.dest_port);
                    message += "  " + std::to_string(src_port) + "  " + std::to_string(dst_port);
                } else if (packet.ip_header.protocol == IPPROTO_UDP) {
                    message += "   udp";
                    int src_port = ntohs(packet.transport_layer.udp_header.src_port);
                    int dst_port = ntohs(packet.transport_layer.udp_header.dest_port);
                    message += "  " + std::to_string(src_port) + "  " + std::to_string(dst_port);
                }
            } else if (ntohs(packet.eth_header.ethertype) == ETHERTYPE_ARP) {
                // parse ARP header
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(packet.arp_header.sender_ip), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(packet.arp_header.target_ip), dst_ip, INET_ADDRSTRLEN);

                message += "  " + std::string(src_ip) + "  " + std::string(dst_ip);
                message += "  arp";
            }

            info_cache.push_back(message);
        }
        packet_mtx.unlock();

        info_mtx.unlock();
    }
}