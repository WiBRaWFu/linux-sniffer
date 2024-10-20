#include "PacketProcessor.hpp"
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string>
#include <thread>
#include <utility>

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
            std::vector<std::pair<std::string, std::string>> packet_info;

            packet_info.emplace_back(std::make_pair("<CAP-LEN>", std::to_string(packet.cap_size)));
            packet_info.emplace_back(std::make_pair("<ORI-LEN>", std::to_string(packet.cap_size)));

            char src_mac[18], dst_mac[18];
            sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    packet.eth_header.src_mac[0], packet.eth_header.src_mac[1],
                    packet.eth_header.src_mac[2], packet.eth_header.src_mac[3],
                    packet.eth_header.src_mac[4], packet.eth_header.src_mac[5]);
            sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    packet.eth_header.dst_mac[0], packet.eth_header.dst_mac[1],
                    packet.eth_header.dst_mac[2], packet.eth_header.dst_mac[3],
                    packet.eth_header.dst_mac[4], packet.eth_header.dst_mac[5]);

            packet_info.emplace_back(std::make_pair("<SRC-MAC>", std::string(src_mac)));
            packet_info.emplace_back(std::make_pair("<DST-MAC>", std::string(dst_mac)));

            if (ntohs(packet.eth_header.ethertype) == ETHERTYPE_IP) {
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(packet.ip_header.src_ip), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(packet.ip_header.dest_ip), dst_ip, INET_ADDRSTRLEN);

                packet_info.emplace_back(std::make_pair("<SRC-IP>", std::string(src_ip)));
                packet_info.emplace_back(std::make_pair("<DST-IP>", std::string(dst_ip)));

                // check for TCP or UDP packets
                if (packet.ip_header.protocol == IPPROTO_TCP) {
                    packet_info.emplace_back(std::make_pair("<PROTOCOL>", "tcp"));

                    int src_port = ntohs(packet.tcp_header.src_port);
                    int dst_port = ntohs(packet.tcp_header.dest_port);

                    if (src_port == 80 || dst_port == 80)
                        packet_info.emplace_back(std::make_pair("<PROTOCOL>", "http"));
                    if (src_port == 443 || dst_port == 443)
                        packet_info.emplace_back(std::make_pair("<PROTOCOL>", "https"));
                    packet_info.emplace_back(std::make_pair("<PAYLOAD>", std::to_string(packet.payload_size)));

                    packet_info.emplace_back(std::make_pair("<SRC-PORT>", std::to_string(src_port)));
                    packet_info.emplace_back(std::make_pair("<DST-PORT>", std::to_string(dst_port)));
                } else if (packet.ip_header.protocol == IPPROTO_UDP) {
                    packet_info.emplace_back(std::make_pair("<PROTOCOL>", "udp"));

                    int src_port = ntohs(packet.udp_header.src_port);
                    int dst_port = ntohs(packet.udp_header.dest_port);

                    packet_info.emplace_back(std::make_pair("<SRC-PORT>", std::to_string(src_port)));
                    packet_info.emplace_back(std::make_pair("<DST-PORT>", std::to_string(dst_port)));
                } else if (packet.ip_header.protocol == IPPROTO_ICMP) {
                    packet_info.emplace_back(std::make_pair("<PROTOCOL>", "icmp"));

                    if (packet.icmp_header.type == ICMP_ECHO) {
                        packet_info.emplace_back(std::make_pair("<TYPE>", "echo"));
                    } else if (packet.icmp_header.type == ICMP_ECHOREPLY) {
                        packet_info.emplace_back(std::make_pair("<TYPE>", "echo reply"));
                    }
                }
            } else if (ntohs(packet.eth_header.ethertype) == ETHERTYPE_ARP) {
                char src_ip[INET_ADDRSTRLEN];
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(packet.arp_header.sender_ip), src_ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(packet.arp_header.target_ip), dst_ip, INET_ADDRSTRLEN);

                packet_info.emplace_back(std::make_pair("<SRC-IP>", std::string(src_ip)));
                packet_info.emplace_back(std::make_pair("<DST-IP>", std::string(dst_ip)));
                packet_info.emplace_back(std::make_pair("<PROTOCOL>", "arp"));
            }

            info_cache.push_back(packet_info);
        }
        packet_mtx.unlock();

        info_mtx.unlock();
    }
}